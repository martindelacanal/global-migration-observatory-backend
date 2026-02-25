const express = require('express');
const router = express.Router();
const { GoogleGenerativeAI } = require('@google/generative-ai');
const multer = require('multer');
const pdf = require('pdf-parse');
const fs = require('fs');
const path = require('path');
const {
    verifyToken,
    mysqlConnection,
    s3,
    bucketName,
    randomImageName,
    PutObjectCommand,
    DeleteObjectCommand,
    GetObjectCommand,
    getSignedUrl,
    crypto
} = require('../utils/sharedHelpers');

// Configuración de multer para archivos PDF
const storage = multer.memoryStorage();
const pdfUpload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Solo permitir archivos PDF
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Solo se permiten archivos PDF'), false);
        }
    },
    limits: {
        fileSize: 100 * 1024 * 1024 // Límite de 10MB
    }
}).single('pdf');

// Función helper para calcular hash del archivo
function calculateFileHash(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Función helper para generar nombre único de archivo
function generatePdfFileName() {
    return randomImageName(); // Reutilizamos la función existente
}

// Configuración de base de datos vectorial simple
const VECTOR_DB_PATH = './vector_data';
const COLLECTION_NAME = 'migration_documents';

// Asegurar que el directorio existe
if (!fs.existsSync(VECTOR_DB_PATH)) {
    fs.mkdirSync(VECTOR_DB_PATH, { recursive: true });
}

// Inicializar Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

function getEnvInt(name, defaultValue, minValue, maxValue) {
    const parsedValue = Number.parseInt(process.env[name], 10);

    if (!Number.isInteger(parsedValue)) {
        return defaultValue;
    }

    return Math.min(maxValue, Math.max(minValue, parsedValue));
}

const CHAT_MODEL_NAME = process.env.GEMINI_CHAT_MODEL || 'gemini-2.5-flash';
const EMBEDDING_MODEL_NAME = process.env.GEMINI_EMBEDDING_MODEL || 'text-embedding-004';
const EMBEDDING_BATCH_SIZE = getEnvInt('GEMINI_EMBEDDING_BATCH_SIZE', 20, 1, 100);
const EMBEDDING_MAX_RETRIES = getEnvInt('GEMINI_EMBEDDING_MAX_RETRIES', 1, 0, 10);
const EMBEDDING_RETRY_BASE_MS = getEnvInt('GEMINI_EMBEDDING_RETRY_BASE_MS', 1200, 250, 60000);
const EMBEDDING_RETRY_MAX_MS = getEnvInt('GEMINI_EMBEDDING_RETRY_MAX_MS', 30000, EMBEDDING_RETRY_BASE_MS, 120000);
const EMBEDDING_INTER_BATCH_DELAY_MS = getEnvInt('GEMINI_EMBEDDING_INTER_BATCH_DELAY_MS', 150, 0, 10000);
const EMBEDDING_FALLBACK_COOLDOWN_MS = getEnvInt('EMBEDDING_FALLBACK_COOLDOWN_MS', 60000, 1000, 300000);
const LOCAL_EMBEDDING_DIMENSION = getEnvInt('LOCAL_EMBEDDING_DIMENSION', 768, 128, 3072);

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function parseRetryDelayMs(delayValue) {
    if (typeof delayValue !== 'string') {
        return null;
    }

    const match = delayValue.trim().match(/^(\d+(?:\.\d+)?)s$/);
    if (!match) {
        return null;
    }

    return Math.ceil(Number.parseFloat(match[1]) * 1000);
}

function getRetryDelayMsFromError(error) {
    if (!error || typeof error !== 'object') {
        return null;
    }

    if (typeof error.retryDelay === 'string') {
        const parsedDelay = parseRetryDelayMs(error.retryDelay);
        if (parsedDelay !== null) {
            return parsedDelay;
        }
    }

    if (!Array.isArray(error.errorDetails)) {
        return null;
    }

    for (const detail of error.errorDetails) {
        if (!detail || typeof detail !== 'object') {
            continue;
        }

        const detailType = String(detail['@type'] || '');
        if (!detailType.includes('RetryInfo') || typeof detail.retryDelay !== 'string') {
            continue;
        }

        const parsedDelay = parseRetryDelayMs(detail.retryDelay);
        if (parsedDelay !== null) {
            return parsedDelay;
        }
    }

    return null;
}

function isRetryableEmbeddingError(error) {
    const statusCode = Number(error?.status);
    if ([429, 500, 502, 503, 504].includes(statusCode)) {
        return true;
    }

    const message = String(error?.message || '').toLowerCase();
    return (
        message.includes('too many requests') ||
        message.includes('rate limit') ||
        message.includes('quota') ||
        message.includes('resource_exhausted') ||
        message.includes('temporarily unavailable') ||
        message.includes('timeout')
    );
}

function getRetryDelayMs(error, attempt) {
    const serverDelayMs = getRetryDelayMsFromError(error);
    if (Number.isInteger(serverDelayMs) && serverDelayMs > 0) {
        return Math.min(EMBEDDING_RETRY_MAX_MS, Math.max(EMBEDDING_RETRY_BASE_MS, serverDelayMs));
    }

    const exponentialDelay = EMBEDDING_RETRY_BASE_MS * Math.pow(2, attempt);
    const jitter = Math.floor(Math.random() * 200);
    return Math.min(EMBEDDING_RETRY_MAX_MS, exponentialDelay + jitter);
}

function unwrapError(error) {
    if (error && typeof error === 'object' && error.cause) {
        return error.cause;
    }
    return error;
}

function shouldFallbackToLocalEmbeddings(error) {
    return isRetryableEmbeddingError(unwrapError(error));
}

function getFallbackCooldownMs(error) {
    const rootError = unwrapError(error);
    const retryDelayMs = getRetryDelayMsFromError(rootError);
    if (Number.isInteger(retryDelayMs) && retryDelayMs > 0) {
        return retryDelayMs;
    }
    return EMBEDDING_FALLBACK_COOLDOWN_MS;
}

// Función de embedding usando Gemini
class GeminiEmbeddingFunction {
    constructor() {
        this.modelName = EMBEDDING_MODEL_NAME;
        this.model = genAI.getGenerativeModel({ model: this.modelName });
        this.batchSize = EMBEDDING_BATCH_SIZE;
        this.maxRetries = EMBEDDING_MAX_RETRIES;
        this.interBatchDelayMs = EMBEDDING_INTER_BATCH_DELAY_MS;
    }

    async embedBatch(batchTexts) {
        let lastError = null;

        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            try {
                const result = await this.model.batchEmbedContents({
                    requests: batchTexts.map(text => ({
                        content: { parts: [{ text }] },
                    })),
                });

                if (!result || !Array.isArray(result.embeddings)) {
                    throw new Error(`Invalid embedding response from model "${this.modelName}".`);
                }

                return result.embeddings.map(embedding => embedding.values);
            } catch (error) {
                lastError = error;
                const canRetry = isRetryableEmbeddingError(error) && attempt < this.maxRetries;

                if (!canRetry) {
                    break;
                }

                const delayMs = getRetryDelayMs(error, attempt);
                console.warn(`[Embeddings] Retry ${attempt + 1}/${this.maxRetries} in ${delayMs}ms (model: ${this.modelName}).`);
                await sleep(delayMs);
            }
        }

        const wrappedError = new Error(`Failed to generate embeddings with Gemini model "${this.modelName}".`);
        wrappedError.status = lastError?.status;
        wrappedError.errorDetails = lastError?.errorDetails;
        wrappedError.cause = lastError;
        throw wrappedError;
    }

    async embed(texts) {
        if (!Array.isArray(texts) || texts.length === 0) {
            return [];
        }

        const allEmbeddings = [];

        // Process texts in batches to respect API limits and smooth request bursts.
        for (let i = 0; i < texts.length; i += this.batchSize) {
            const batchTexts = texts.slice(i, i + this.batchSize);
            const batchEmbeddings = await this.embedBatch(batchTexts);
            allEmbeddings.push(...batchEmbeddings);

            const hasMoreBatches = i + this.batchSize < texts.length;
            if (hasMoreBatches && this.interBatchDelayMs > 0) {
                await sleep(this.interBatchDelayMs);
            }
        }

        return allEmbeddings;
    }
}

class SimpleEmbeddingFunction {
    constructor() {
        this.dimension = LOCAL_EMBEDDING_DIMENSION;
    }

    async embed(texts) {
        return texts.map(text => {
            const normalized = String(text || '').toLowerCase().replace(/[^\w\s]/g, ' ');
            const words = normalized.split(/\s+/).filter(word => word.length > 1);
            const embedding = new Array(this.dimension).fill(0);

            if (words.length === 0) {
                return embedding;
            }

            const frequencies = new Map();
            for (const word of words) {
                frequencies.set(word, (frequencies.get(word) || 0) + 1);
            }

            for (const [word, count] of frequencies.entries()) {
                const weight = 1 + Math.log(count);
                const primaryHash = this.simpleHash(word, 0x9e3779b9);
                const secondaryHash = this.simpleHash(word, 0x85ebca6b);

                const primaryIndex = primaryHash % this.dimension;
                const secondaryIndex = secondaryHash % this.dimension;
                const primarySign = (primaryHash & 1) === 0 ? 1 : -1;
                const secondarySign = (secondaryHash & 1) === 0 ? 1 : -1;

                embedding[primaryIndex] += weight * primarySign;
                embedding[secondaryIndex] += (weight * 0.5) * secondarySign;
            }

            const magnitude = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
            if (magnitude > 0) {
                for (let i = 0; i < embedding.length; i++) {
                    embedding[i] /= magnitude;
                }
            }

            return embedding;
        });
    }

    simpleHash(str, seed = 0) {
        let hash = (2166136261 ^ seed) >>> 0;
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash = Math.imul(hash, 16777619);
            hash >>>= 0;
        }
        return hash;
    }
}

class ResilientEmbeddingFunction {
    constructor() {
        this.geminiEmbedding = new GeminiEmbeddingFunction();
        this.localEmbedding = new SimpleEmbeddingFunction();
        this.fallbackUntil = 0;
    }

    async embed(texts) {
        if (Date.now() < this.fallbackUntil) {
            return this.localEmbedding.embed(texts);
        }

        try {
            return await this.geminiEmbedding.embed(texts);
        } catch (error) {
            if (!shouldFallbackToLocalEmbeddings(error)) {
                throw error;
            }

            const cooldownMs = getFallbackCooldownMs(error);
            this.fallbackUntil = Date.now() + cooldownMs;
            console.warn(`[Embeddings] Gemini is temporarily unavailable. Using local fallback for ${Math.ceil(cooldownMs / 1000)}s.`);
            return this.localEmbedding.embed(texts);
        }
    }
}
// Clase para manejar la base de datos vectorial simple
class SimpleVectorDB {
    constructor() {
        this.embeddingFunction = new ResilientEmbeddingFunction();
        this.collectionPath = path.join(VECTOR_DB_PATH, `${COLLECTION_NAME}.json`);
        this.collection = this.loadCollection();
    }

    loadCollection() {
        try {
            if (fs.existsSync(this.collectionPath)) {
                const data = fs.readFileSync(this.collectionPath, 'utf8');
                return JSON.parse(data);
            }
        } catch (error) {
            console.error('Error loading collection:', error);
        }
        return {
            name: COLLECTION_NAME,
            documents: [],
            metadata: { created_at: new Date().toISOString() }
        };
    }

    saveCollection() {
        try {
            fs.writeFileSync(this.collectionPath, JSON.stringify(this.collection, null, 2));
        } catch (error) {
            console.error('Error saving collection:', error);
            throw error;
        }
    }

    async add({ ids, documents, metadatas }) {
        try {
            const embeddings = await this.embeddingFunction.embed(documents);
            if (!Array.isArray(embeddings) || embeddings.length !== ids.length) {
                throw new Error('Embedding count does not match document count.');
            }

            for (let i = 0; i < ids.length; i++) {
                const embeddingVector = embeddings[i];
                if (!Array.isArray(embeddingVector) || embeddingVector.length === 0) {
                    continue;
                }

                // Verificar si el documento ya existe
                const existingIndex = this.collection.documents.findIndex(doc => doc.id === ids[i]);

                const documentData = {
                    id: ids[i],
                    document: documents[i],
                    metadata: metadatas[i],
                    embedding: embeddingVector,
                    created_at: new Date().toISOString()
                };

                if (existingIndex >= 0) {
                    // Actualizar documento existente
                    this.collection.documents[existingIndex] = documentData;
                } else {
                    // Agregar nuevo documento
                    this.collection.documents.push(documentData);
                }
            }

            this.saveCollection();
        } catch (error) {
            console.error('Error adding documents:', error);
            throw error;
        }
    }

    async query({ queryTexts, nResults = 5, include = ['documents', 'metadatas', 'distances'] }) {
        try {
            if (this.collection.documents.length === 0) {
                return {
                    documents: [[]],
                    metadatas: [[]],
                    distances: [[]]
                };
            }

            const queryEmbeddings = await this.embeddingFunction.embed(queryTexts);
            if (!Array.isArray(queryEmbeddings) || queryEmbeddings.length === 0 || !Array.isArray(queryEmbeddings[0])) {
                return {
                    documents: [[]],
                    metadatas: [[]],
                    distances: [[]]
                };
            }

            const queryEmbedding = queryEmbeddings[0];

            // Calcular similitudes coseno
            const similarities = this.collection.documents
                .filter(doc => Array.isArray(doc.embedding) && doc.embedding.length > 0)
                .map(doc => {
                    const similarity = this.cosineSimilarity(queryEmbedding, doc.embedding);
                    return {
                        ...doc,
                        similarity: similarity,
                        distance: 1 - similarity // Convertir similitud a distancia
                    };
                });

            if (similarities.length === 0) {
                return {
                    documents: [[]],
                    metadatas: [[]],
                    distances: [[]]
                };
            }

            // Ordenar por similitud (mayor a menor)
            similarities.sort((a, b) => b.similarity - a.similarity);

            // Tomar los mejores resultados
            const topResults = similarities.slice(0, nResults);

            const result = {
                documents: [[]],
                metadatas: [[]],
                distances: [[]]
            };

            if (include.includes('documents')) {
                result.documents[0] = topResults.map(r => r.document);
            }
            if (include.includes('metadatas')) {
                result.metadatas[0] = topResults.map(r => r.metadata);
            }
            if (include.includes('distances')) {
                result.distances[0] = topResults.map(r => r.distance);
            }

            return result;
        } catch (error) {
            console.error('Error querying documents:', error);
            throw error;
        }
    }

    async get({ where }) {
        try {
            let filteredDocs = this.collection.documents;

            if (where) {
                filteredDocs = this.collection.documents.filter(doc => {
                    return Object.keys(where).every(key => {
                        return doc.metadata[key] === where[key];
                    });
                });
            }

            return {
                ids: filteredDocs.map(doc => doc.id),
                documents: filteredDocs.map(doc => doc.document),
                metadatas: filteredDocs.map(doc => doc.metadata)
            };
        } catch (error) {
            console.error('Error getting documents:', error);
            throw error;
        }
    }

    async delete({ where }) {
        try {
            const initialCount = this.collection.documents.length;

            if (where) {
                this.collection.documents = this.collection.documents.filter(doc => {
                    return !Object.keys(where).every(key => {
                        return doc.metadata[key] === where[key];
                    });
                });
            }

            this.saveCollection();
            const deletedCount = initialCount - this.collection.documents.length;
            return deletedCount;
        } catch (error) {
            console.error('Error deleting documents:', error);
            throw error;
        }
    }

    cosineSimilarity(vecA, vecB) {
        if (!Array.isArray(vecA) || !Array.isArray(vecB) || vecA.length === 0 || vecB.length === 0) {
            return 0;
        }

        const dimensions = Math.min(vecA.length, vecB.length);
        if (dimensions === 0) {
            return 0;
        }

        let dotProduct = 0;
        let magnitudeASquared = 0;
        let magnitudeBSquared = 0;

        for (let i = 0; i < dimensions; i++) {
            const a = Number(vecA[i]) || 0;
            const b = Number(vecB[i]) || 0;
            dotProduct += a * b;
            magnitudeASquared += a * a;
            magnitudeBSquared += b * b;
        }

        const magnitudeA = Math.sqrt(magnitudeASquared);
        const magnitudeB = Math.sqrt(magnitudeBSquared);
        if (magnitudeA === 0 || magnitudeB === 0) {
            return 0;
        }

        return dotProduct / (magnitudeA * magnitudeB);
    }
}

// Instancia global de la base de datos vectorial
const vectorDB = new SimpleVectorDB();

// Función para dividir texto en fragmentos (chunks)
function chunkText(text, chunkSize = 1000, overlap = 200) {
    const chunks = [];
    const sentences = text.split(/[.!?]+/).filter(sentence => sentence.trim().length > 0);

    let currentChunk = '';

    for (const sentence of sentences) {
        if ((currentChunk + sentence).length <= chunkSize) {
            currentChunk += sentence + '. ';
        } else {
            if (currentChunk.trim()) {
                chunks.push(currentChunk.trim());
            }
            currentChunk = sentence + '. ';
        }
    }

    if (currentChunk.trim()) {
        chunks.push(currentChunk.trim());
    }

    return chunks.filter(chunk => chunk.length > 50); // Filtrar chunks muy pequeños
}

// Función para obtener la colección de la base de datos vectorial
async function getOrCreateCollection() {
    try {
        // Simplemente retornamos la instancia de vectorDB
        return vectorDB;
    } catch (error) {
        console.error('Error getting/creating vector collection:', error);
        throw error;
    }
}

// Función para indexar un documento PDF
async function indexPdfDocument(s3Key, originalFilename, documentId) {
    try {
        // Descargar el PDF desde S3
        const command = new GetObjectCommand({
            Bucket: bucketName,
            Key: s3Key
        });

        const response = await s3.send(command);
        const chunks = [];

        for await (const chunk of response.Body) {
            chunks.push(chunk);
        }

        const buffer = Buffer.concat(chunks);

        // Extraer texto del PDF
        const pdfData = await pdf(buffer);
        const text = pdfData.text.replace(/\s+/g, ' ').trim();

        if (!text || text.length < 100) {
            throw new Error('No se pudo extraer texto suficiente del PDF');
        }

        // Dividir en fragmentos
        const textChunks = chunkText(text);

        if (textChunks.length === 0) {
            throw new Error('No se pudieron crear fragmentos de texto válidos');
        }

        // Obtener la colección
        const collection = await getOrCreateCollection();

        // Preparar datos para la base de datos vectorial
        const ids = textChunks.map((_, index) => `${s3Key}-chunk-${index}`);
        const metadatas = textChunks.map((chunk, index) => ({
            source_s3_key: s3Key,
            original_filename: originalFilename,
            document_id: documentId.toString(),
            chunk_index: index,
            chunk_length: chunk.length,
            indexed_at: new Date().toISOString()
        }));

        // Agregar documentos a la base de datos vectorial
        await collection.add({
            ids: ids,
            documents: textChunks,
            metadatas: metadatas
        });

        return textChunks.length;

    } catch (error) {
        console.error(`Error indexando documento ${originalFilename}:`, error);
        throw error;
    }
}

// Función para eliminar un documento de la base de datos vectorial
async function removeDocumentFromIndex(s3Key) {
    try {
        const collection = await getOrCreateCollection();

        // Obtener todos los fragmentos del documento
        const results = await collection.get({
            where: { source_s3_key: s3Key }
        });

        if (results.ids.length > 0) {
            // Eliminar todos los fragmentos del documento
            const deletedCount = await collection.delete({
                where: { source_s3_key: s3Key }
            });

            return deletedCount;
        }

        return 0;
    } catch (error) {
        console.error(`Error eliminando documento ${s3Key} de la base de datos vectorial:`, error);
        throw error;
    }
}

// Función para buscar documentos relevantes
async function searchRelevantDocuments(query, nResults = 5) {
    try {
        const collection = await getOrCreateCollection();

        const results = await collection.query({
            queryTexts: [query],
            nResults: nResults,
            include: ['documents', 'metadatas', 'distances']
        });

        return results;
    } catch (error) {
        console.error('Error buscando documentos relevantes:', error);
        throw error;
    }
}



// GET - Obtener todas las sesiones de chat de un usuario
router.get('/chat/sessions', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
        return res.status(401).json('Unauthorized');
    }

    const userId = cabecera.id;

    const query = `
        SELECT cs.*, 
               (SELECT content FROM chat_messages cm 
                WHERE cm.session_id = cs.id 
                ORDER BY cm.creation_date DESC LIMIT 1) as last_message,
               (SELECT COUNT(*) FROM chat_messages cm 
                WHERE cm.session_id = cs.id) as message_count
        FROM chat_sessions cs 
        WHERE cs.user_id = ?
        ORDER BY cs.modification_date DESC
    `;

    mysqlConnection.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error getting chat sessions:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al obtener las sesiones de chat'
            });
        }

        res.json({
            success: true,
            sessions: results
        });
    });
});

// POST - Crear nueva sesión de chat
router.post('/chat/sessions', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
        return res.status(401).json('Unauthorized');
    }

    const userId = cabecera.id;
    const { title = 'Nueva conversación' } = req.body;

    if (!userId) {
        return res.status(400).json({
            success: false,
            message: 'user_id es requerido'
        });
    }

    const query = 'INSERT INTO chat_sessions (user_id, title) VALUES (?, ?)';

    mysqlConnection.query(query, [userId, title], (err, result) => {
        if (err) {
            console.error('Error creating chat session:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al crear la sesión de chat'
            });
        }

        res.json({
            success: true,
            sessionId: result.insertId,
            message: 'Sesión de chat creada exitosamente'
        });
    });
});

// GET - Obtener historial de mensajes de una sesión
router.get('/chat/messages/:sessionId', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
        return res.status(401).json('Unauthorized');
    }

    const sessionId = req.params.sessionId;

    const query = `
        SELECT * FROM chat_messages 
        WHERE session_id = ? 
        ORDER BY creation_date ASC
    `;

    mysqlConnection.query(query, [sessionId], (err, results) => {
        if (err) {
            console.error('Error getting chat messages:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al obtener los mensajes'
            });
        }

        res.json({
            success: true,
            messages: results
        });
    });
});

// POST - Enviar mensaje y obtener respuesta de Gemini con RAG
router.post('/chat/message', verifyToken, async (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
        return res.status(401).json('Unauthorized');
    }

    const userId = cabecera.id;
    const { sessionId, message } = req.body;

    if (!sessionId || !message || !userId) {
        return res.status(400).json({
            success: false,
            message: 'sessionId y message son requeridos'
        });
    }

    try {
        // Verificar que la sesión pertenece al usuario
        const sessionQuery = 'SELECT * FROM chat_sessions WHERE id = ? AND user_id = ?';

        mysqlConnection.query(sessionQuery, [sessionId, userId], async (err, sessionResults) => {
            if (err) {
                console.error('Error verifying session:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error al verificar la sesión'
                });
            }

            if (sessionResults.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Sesión no encontrada'
                });
            }

            // Obtener historial de la conversación
            const historyQuery = `
                SELECT role, content FROM chat_messages 
                WHERE session_id = ? 
                ORDER BY creation_date ASC
            `;

            mysqlConnection.query(historyQuery, [sessionId], async (err, historyResults) => {
                if (err) {
                    console.error('Error getting conversation history:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error al obtener el historial'
                    });
                }

                try {
                    // Guardar mensaje del usuario
                    const userMessageQuery = 'INSERT INTO chat_messages (session_id, role, content) VALUES (?, ?, ?)';

                    mysqlConnection.query(userMessageQuery, [sessionId, 'user', message], async (err, userMessageResult) => {
                        if (err) {
                            console.error('Error saving user message:', err);
                            return res.status(500).json({
                                success: false,
                                message: 'Error al guardar el mensaje'
                            });
                        }

                        try {
                            // ============ IMPLEMENTACIÓN RAG ============

                            // 1. Buscar documentos relevantes en la base de datos vectorial
                            let relevantContext = '';
                            let documentsUsed = [];

                            try {
                                const searchResults = await searchRelevantDocuments(message, 5);

                                if (searchResults.documents && searchResults.documents[0] && searchResults.documents[0].length > 0) {
                                    // Construir contexto desde los documentos encontrados
                                    const documents = searchResults.documents[0];
                                    const metadatas = searchResults.metadatas[0];
                                    const distances = searchResults.distances[0];

                                    for (let i = 0; i < documents.length; i++) {

                                        if (distances[i] < 1.2) { // Ajustado el umbral para ser menos restrictivo
                                            relevantContext += `\n--- Fragmento ${i + 1} (${metadatas[i].original_filename}) ---\n`;
                                            relevantContext += documents[i] + '\n';

                                            if (!documentsUsed.includes(metadatas[i].original_filename)) {
                                                documentsUsed.push(metadatas[i].original_filename);
                                            }
                                        }
                                    }

                                } else {
                                    relevantContext = "No se encontraron documentos relevantes en la base de conocimiento.";
                                }
                            } catch (searchError) {
                                console.error('Error searching documents:', searchError);
                                relevantContext = "Error al buscar en la base de conocimiento.";
                            }

                            // 2. Obtener el prompt personalizado de la base de datos
                            const promptQuery = 'SELECT prompt FROM chat_prompt ORDER BY modification_date DESC LIMIT 1';

                            mysqlConnection.query(promptQuery, [], async (err, promptResults) => {
                                if (err) {
                                    console.error('Error getting chat prompt:', err);
                                }

                                let baseSystemInstruction = promptResults && promptResults.length > 0 && promptResults[0].prompt
                                    ? promptResults[0].prompt
                                    : "Eres un asistente especializado en migración global. Proporciona información precisa y actualizada sobre temas relacionados con migración, políticas migratorias, estadísticas demográficas y tendencias globales.";

                                // 3. Construir el prompt con RAG
                                const systemInstructionWithRAG = `${baseSystemInstruction}

INSTRUCCIONES IMPORTANTES:
- Debes responder ÚNICAMENTE basándote en la información proporcionada en el CONTEXTO DE DOCUMENTOS que aparece a continuación.
- Los encabezados como "--- Fragmento X (nombre_archivo.pdf) ---" son solo para tu referencia. NO los incluyas en tu respuesta.
- Si la pregunta no puede ser respondida con la información del contexto, indica claramente que no tienes esa información en tus documentos.
- NO inventes información que no esté en el contexto.
- Cita el nombre del archivo (por ejemplo, "según el documento 'nombre_archivo.pdf'...") solo si es necesario para dar claridad a la respuesta. No cites los números de fragmento.
- Si no hay documentos relevantes disponibles, informa al usuario que no tienes información suficiente en la base de conocimiento.

CONTEXTO DE DOCUMENTOS:
${relevantContext}

Pregunta del usuario: ${message}

Responde de forma natural y fluida, basándote únicamente en el contexto proporcionado arriba.`;

                                // 4. Construir historial de conversación para mantener contexto
                                let conversationHistory = [];
                                historyResults.forEach(msg => {
                                    conversationHistory.push({
                                        role: msg.role === 'user' ? 'user' : 'model',
                                        parts: [{ text: msg.content }]
                                    });
                                });

                                // Construir el contenido completo incluyendo historial
                                let fullContent = '';

                                // Agregar historial de conversación si existe
                                if (conversationHistory.length > 0) {
                                    fullContent += "HISTORIAL DE CONVERSACIÓN:\n";
                                    conversationHistory.forEach(msg => {
                                        const role = msg.role === 'user' ? 'Usuario' : 'Asistente';
                                        fullContent += `${role}: ${msg.parts[0].text}\n`;
                                    });
                                    fullContent += "\n";
                                }

                                fullContent += `Nueva pregunta del usuario: ${message}`;

                                try {
                                    // 5. Llamar a Gemini con RAG
                                    const model = genAI.getGenerativeModel({
                                        model: CHAT_MODEL_NAME,
                                        systemInstruction: systemInstructionWithRAG,
                                        generationConfig: {
                                            temperature: 1,
                                            maxOutputTokens: 2000
                                        }
                                    });

                                    const result = await model.generateContent(fullContent);
                                    const response = await result.response;
                                    const aiResponse = response.text();

                                    // 6. Guardar respuesta de la IA
                                    const aiMessageQuery = 'INSERT INTO chat_messages (session_id, role, content) VALUES (?, ?, ?)';

                                    mysqlConnection.query(aiMessageQuery, [sessionId, 'assistant', aiResponse], (err, aiMessageResult) => {
                                        if (err) {
                                            console.error('Error saving AI message:', err);
                                            return res.status(500).json({
                                                success: false,
                                                message: 'Error al guardar la respuesta de la IA'
                                            });
                                        }

                                        // 7. Actualizar timestamp de la sesión
                                        const updateSessionQuery = 'UPDATE chat_sessions SET modification_date = CURRENT_TIMESTAMP WHERE id = ?';
                                        mysqlConnection.query(updateSessionQuery, [sessionId], (err) => {
                                            if (err) {
                                                console.error('Error updating session timestamp:', err);
                                            }
                                        });

                                        // 8. Responder con información adicional sobre RAG
                                        res.json({
                                            success: true,
                                            userMessage: {
                                                id: userMessageResult.insertId,
                                                role: 'user',
                                                content: message,
                                                creation_date: new Date()
                                            },
                                            aiResponse: {
                                                id: aiMessageResult.insertId,
                                                role: 'assistant',
                                                content: aiResponse,
                                                creation_date: new Date()
                                            },
                                            ragInfo: {
                                                documentsUsed: documentsUsed,
                                                documentsCount: documentsUsed.length,
                                                hasRelevantContext: relevantContext !== "No se encontraron documentos relevantes en la base de conocimiento."
                                            }
                                        });
                                    });

                                } catch (aiError) {
                                    console.error('Error calling Gemini AI:', aiError);
                                    res.status(500).json({
                                        success: false,
                                        message: 'Error al obtener respuesta de la IA'
                                    });
                                }
                            });

                        } catch (ragError) {
                            console.error('Error in RAG process:', ragError);
                            res.status(500).json({
                                success: false,
                                message: 'Error en el proceso de búsqueda y generación'
                            });
                        }
                    });

                } catch (innerError) {
                    console.error('Error in inner try block:', innerError);
                    res.status(500).json({
                        success: false,
                        message: 'Error al procesar el mensaje'
                    });
                }
            });
        });

    } catch (error) {
        console.error('General error in chat message endpoint:', error);
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
});

// DELETE - Eliminar sesión de chat
router.delete('/chat/sessions/:sessionId', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
        return res.status(401).json('Unauthorized');
    }

    const userId = cabecera.id;

    const { sessionId } = req.params;

    if (!userId) {
        return res.status(400).json({
            success: false,
            message: 'userId es requerido'
        });
    }

    // Verificar que la sesión pertenece al usuario antes de eliminar
    const deleteQuery = 'DELETE FROM chat_sessions WHERE id = ? AND user_id = ?';

    mysqlConnection.query(deleteQuery, [sessionId, userId], (err, result) => {
        if (err) {
            console.error('Error deleting chat session:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al eliminar la sesión'
            });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sesión no encontrada o no tienes permisos para eliminarla'
            });
        }

        res.json({
            success: true,
            message: 'Sesión eliminada exitosamente'
        });
    });
});

// PATCH - Actualizar título de sesión
router.patch('/chat/sessions/:sessionId', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
        return res.status(401).json('Unauthorized');
    }

    const userId = cabecera.id;

    const { sessionId } = req.params;
    const { title } = req.body;

    if (!title || !userId) {
        return res.status(400).json({
            success: false,
            message: 'title y userId son requeridos'
        });
    }

    const updateQuery = 'UPDATE chat_sessions SET title = ? WHERE id = ? AND user_id = ?';

    mysqlConnection.query(updateQuery, [title, sessionId, userId], (err, result) => {
        if (err) {
            console.error('Error updating chat session title:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al actualizar el título'
            });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sesión no encontrada o no tienes permisos para editarla'
            });
        }

        res.json({
            success: true,
            message: 'Título actualizado exitosamente'
        });
    });
});

// GET - Obtener el prompt actual del chatbot (solo admin)
router.get('/chat/prompt', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin') {
        return res.status(401).json('Unauthorized');
    }

    const query = 'SELECT * FROM chat_prompt ORDER BY modification_date DESC LIMIT 1';

    mysqlConnection.query(query, [], (err, results) => {
        if (err) {
            console.error('Error getting chat prompt:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al obtener el prompt del chatbot'
            });
        }

        if (results.length === 0) {
            return res.json({
                success: true,
                prompt: null,
                message: 'No hay prompt configurado'
            });
        }

        res.json({
            success: true,
            prompt: results[0]
        });
    });
});

// POST - Crear o actualizar el prompt del chatbot (solo admin)
router.post('/chat/prompt', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin') {
        return res.status(401).json('Unauthorized');
    }

    const { prompt } = req.body;

    if (!prompt || prompt.trim() === '') {
        return res.status(400).json({
            success: false,
            message: 'El prompt es requerido y no puede estar vacío'
        });
    }

    // Primero verificar si existe un prompt
    const checkQuery = 'SELECT id FROM chat_prompt ORDER BY modification_date DESC LIMIT 1';

    mysqlConnection.query(checkQuery, [], (err, checkResults) => {
        if (err) {
            console.error('Error checking existing prompt:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al verificar el prompt existente'
            });
        }

        if (checkResults.length > 0) {
            // Actualizar el prompt existente
            const updateQuery = 'UPDATE chat_prompt SET prompt = ?, modification_date = CURRENT_TIMESTAMP WHERE id = ?';

            mysqlConnection.query(updateQuery, [prompt.trim(), checkResults[0].id], (err, updateResult) => {
                if (err) {
                    console.error('Error updating chat prompt:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error al actualizar el prompt del chatbot'
                    });
                }

                res.json({
                    success: true,
                    message: 'Prompt del chatbot actualizado exitosamente',
                    promptId: checkResults[0].id
                });
            });
        } else {
            // Crear nuevo prompt
            const insertQuery = 'INSERT INTO chat_prompt (prompt) VALUES (?)';

            mysqlConnection.query(insertQuery, [prompt.trim()], (err, insertResult) => {
                if (err) {
                    console.error('Error creating chat prompt:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error al crear el prompt del chatbot'
                    });
                }

                res.json({
                    success: true,
                    message: 'Prompt del chatbot creado exitosamente',
                    promptId: insertResult.insertId
                });
            });
        }
    });
});

// POST - Subir archivo PDF (solo admin)
router.post('/chat/documents', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin') {
        return res.status(401).json('Unauthorized');
    }

    pdfUpload(req, res, async (err) => {
        if (err) {
            console.error('Error uploading PDF:', err);
            if (err.message === 'Solo se permiten archivos PDF') {
                return res.status(400).json({
                    success: false,
                    message: 'Solo se permiten archivos PDF'
                });
            }
            return res.status(500).json({
                success: false,
                message: 'Error al procesar el archivo'
            });
        }

        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No se proporcionó ningún archivo PDF'
            });
        }

        try {
            const userId = cabecera.id;
            const file = req.file;

            // Calcular hash del archivo
            const fileHash = calculateFileHash(file.buffer);

            // Verificar si ya existe un archivo con el mismo hash
            const checkQuery = 'SELECT id, original_filename FROM chat_pdf_documents WHERE file_hash = ?';

            mysqlConnection.query(checkQuery, [fileHash], async (err, existingFiles) => {
                if (err) {
                    console.error('Error checking for duplicate files:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Error al verificar archivos duplicados'
                    });
                }

                if (existingFiles.length > 0) {
                    return res.status(409).json({
                        success: false,
                        message: `Ya existe un archivo idéntico: ${existingFiles[0].original_filename}`,
                        existingFileId: existingFiles[0].id
                    });
                }

                try {
                    // Generar nombre único para S3
                    const s3Key = generatePdfFileName();

                    // Subir archivo a S3
                    const uploadParams = {
                        Bucket: bucketName,
                        Key: s3Key,
                        Body: file.buffer,
                        ContentType: 'application/pdf',
                        Metadata: {
                            'original-filename': file.originalname,
                            'uploaded-by': userId.toString()
                        }
                    };

                    const command = new PutObjectCommand(uploadParams);
                    await s3.send(command);

                    // Guardar información en la base de datos
                    const insertQuery = `
                        INSERT INTO chat_pdf_documents 
                        (original_filename, s3_key, s3_bucket, file_hash, uploaded_by_user_id) 
                        VALUES (?, ?, ?, ?, ?)
                    `;

                    mysqlConnection.query(insertQuery, [
                        file.originalname,
                        s3Key,
                        bucketName,
                        fileHash,
                        userId
                    ], async (err, result) => {
                        if (err) {
                            console.error('Error saving PDF to database:', err);

                            // Si falla la BD, intentar eliminar el archivo de S3
                            const deleteCommand = new DeleteObjectCommand({
                                Bucket: bucketName,
                                Key: s3Key
                            });
                            s3.send(deleteCommand).catch(s3Error => {
                                console.error('Error cleaning up S3 file after DB failure:', s3Error);
                            });

                            return res.status(500).json({
                                success: false,
                                message: 'Error al guardar la información del archivo'
                            });
                        }

                        const documentId = result.insertId;

                        // Intentar indexar el documento en la base de datos vectorial
                        try {
                            // Actualizar estado a INDEXING
                            mysqlConnection.query(
                                'UPDATE chat_pdf_documents SET status = ? WHERE id = ?',
                                ['INDEXING', documentId],
                                () => { }
                            );

                            const chunksCreated = await indexPdfDocument(s3Key, file.originalname, documentId);

                            // Actualizar estado a INDEXED
                            mysqlConnection.query(
                                'UPDATE chat_pdf_documents SET status = ?, indexed_at = CURRENT_TIMESTAMP WHERE id = ?',
                                ['INDEXED', documentId],
                                (updateErr) => {
                                    if (updateErr) {
                                        console.error('Error updating document status to INDEXED:', updateErr);
                                    }
                                }
                            );

                            res.json({
                                success: true,
                                message: 'Archivo PDF subido e indexado exitosamente',
                                document: {
                                    id: documentId,
                                    originalFilename: file.originalname,
                                    s3Key: s3Key,
                                    fileHash: fileHash,
                                    status: 'INDEXED',
                                    uploadedBy: userId,
                                    creationDate: new Date().toISOString(),
                                    chunksCreated: chunksCreated
                                }
                            });

                        } catch (indexError) {
                            console.error('Error indexing document:', indexError);

                            // Actualizar estado a ERROR
                            mysqlConnection.query(
                                'UPDATE chat_pdf_documents SET status = ? WHERE id = ?',
                                ['ERROR', documentId],
                                () => { }
                            );

                            // El archivo ya está en S3 y en la BD, pero falló la indexación
                            res.json({
                                success: true,
                                message: 'Archivo PDF subido pero falló la indexación',
                                warning: 'El documento se guardó pero no está disponible para búsqueda',
                                document: {
                                    id: documentId,
                                    originalFilename: file.originalname,
                                    s3Key: s3Key,
                                    fileHash: fileHash,
                                    status: 'ERROR',
                                    uploadedBy: userId,
                                    creationDate: new Date().toISOString(),
                                    indexError: indexError.message
                                }
                            });
                        }
                    });

                } catch (s3Error) {
                    console.error('Error uploading to S3:', s3Error);
                    res.status(500).json({
                        success: false,
                        message: 'Error al subir el archivo a S3'
                    });
                }
            });

        } catch (error) {
            console.error('General error uploading PDF:', error);
            res.status(500).json({
                success: false,
                message: 'Error interno del servidor'
            });
        }
    });
});

// GET - Obtener lista de documentos PDF (solo admin)
router.get('/chat/documents', verifyToken, (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin') {
        return res.status(401).json('Unauthorized');
    }

    const query = `
        SELECT 
            id,
            original_filename,
            s3_key,
            file_hash,
            status,
            uploaded_by_user_id,
            creation_date,
            indexed_at
        FROM chat_pdf_documents 
        ORDER BY creation_date DESC
    `;

    mysqlConnection.query(query, [], (err, results) => {
        if (err) {
            console.error('Error getting PDF documents:', err);
            return res.status(500).json({
                success: false,
                message: 'Error al obtener los documentos PDF'
            });
        }

        res.json({
            success: true,
            documents: results
        });
    });
});

// GET - Obtener URL firmada de un documento PDF específico (solo admin)
router.get('/chat/documents/:id/url', verifyToken, async (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin') {
        return res.status(401).json('Unauthorized');
    }

    const { id } = req.params;

    try {
        // Buscar el documento en la base de datos
        const query = 'SELECT s3_key, original_filename FROM chat_pdf_documents WHERE id = ?';

        mysqlConnection.query(query, [id], async (err, results) => {
            if (err) {
                console.error('Error getting PDF document:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error al buscar el documento'
                });
            }

            if (results.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Documento no encontrado'
                });
            }

            const document = results[0];

            try {
                // Generar URL firmada para acceso temporal al archivo
                const command = new GetObjectCommand({
                    Bucket: bucketName,
                    Key: document.s3_key
                });

                const signedUrl = await getSignedUrl(s3, command, { expiresIn: 3600 }); // 1 hora

                res.json({
                    success: true,
                    url: signedUrl,
                    originalFilename: document.original_filename,
                    expiresIn: 3600 // segundos
                });

            } catch (s3Error) {
                console.error('Error generating signed URL:', s3Error);
                res.status(500).json({
                    success: false,
                    message: 'Error al generar el enlace de descarga'
                });
            }
        });

    } catch (error) {
        console.error('General error getting PDF URL:', error);
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
});

// DELETE - Eliminar documento PDF (solo admin)
router.delete('/chat/documents/:id', verifyToken, async (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin') {
        return res.status(401).json('Unauthorized');
    }

    const { id } = req.params;

    try {
        // Primero obtener la información del documento para eliminar de S3
        const selectQuery = 'SELECT s3_key, original_filename FROM chat_pdf_documents WHERE id = ?';

        mysqlConnection.query(selectQuery, [id], async (err, results) => {
            if (err) {
                console.error('Error finding PDF document:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error al buscar el documento'
                });
            }

            if (results.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Documento no encontrado'
                });
            }

            const document = results[0];

            try {
                // Eliminar archivo de S3
                const deleteCommand = new DeleteObjectCommand({
                    Bucket: bucketName,
                    Key: document.s3_key
                });

                await s3.send(deleteCommand);

                // Eliminar de la base de datos vectorial
                try {
                    const deletedChunks = await removeDocumentFromIndex(document.s3_key);
                } catch (vectorError) {
                    console.error('Error eliminando de la base de datos vectorial (continuando con BD):', vectorError);
                }

                // Eliminar registro de la base de datos
                const deleteQuery = 'DELETE FROM chat_pdf_documents WHERE id = ?';

                mysqlConnection.query(deleteQuery, [id], (err, deleteResult) => {
                    if (err) {
                        console.error('Error deleting PDF document from database:', err);
                        return res.status(500).json({
                            success: false,
                            message: 'Error al eliminar el documento de la base de datos'
                        });
                    }

                    if (deleteResult.affectedRows === 0) {
                        return res.status(404).json({
                            success: false,
                            message: 'Documento no encontrado para eliminar'
                        });
                    }

                    res.json({
                        success: true,
                        message: `Documento "${document.original_filename}" eliminado exitosamente de S3, base de datos vectorial y base de datos`
                    });
                });

            } catch (s3Error) {
                console.error('Error deleting from S3:', s3Error);

                // Incluso si falla S3, intentar eliminar de la base de datos vectorial y BD
                try {
                    await removeDocumentFromIndex(document.s3_key);
                } catch (vectorError) {
                    console.error('Error eliminando de la base de datos vectorial después de fallo S3:', vectorError);
                }

                const deleteQuery = 'DELETE FROM chat_pdf_documents WHERE id = ?';
                mysqlConnection.query(deleteQuery, [id], (err, deleteResult) => {
                    if (err) {
                        console.error('Error deleting PDF document from database after S3 failure:', err);
                        return res.status(500).json({
                            success: false,
                            message: 'Error al eliminar el documento completamente'
                        });
                    }

                    res.json({
                        success: true,
                        message: `Documento "${document.original_filename}" eliminado de la base de datos y base de datos vectorial (advertencia: posible archivo huérfano en S3)`,
                        warning: 'El archivo podría seguir existiendo en S3'
                    });
                });
            }
        });

    } catch (error) {
        console.error('General error deleting PDF:', error);
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
});

// POST - Re-indexar documentos pendientes o con error (solo admin)
router.post('/chat/documents/reindex', verifyToken, async (req, res) => {
    const cabecera = JSON.parse(req.data.data);

    if (cabecera.role !== 'admin') {
        return res.status(401).json('Unauthorized');
    }

    try {
        // Obtener documentos pendientes o con error
        const query = `
            SELECT id, original_filename, s3_key
            FROM chat_pdf_documents 
            WHERE status IN ('PENDING', 'ERROR')
            ORDER BY creation_date ASC
        `;

        mysqlConnection.query(query, [], async (err, pendingDocs) => {
            if (err) {
                console.error('Error getting pending documents:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Error al obtener documentos pendientes'
                });
            }

            if (pendingDocs.length === 0) {
                return res.json({
                    success: true,
                    message: 'No hay documentos pendientes de indexación',
                    processedCount: 0
                });
            }

            let successCount = 0;
            let errorCount = 0;
            const results = [];

            // Procesar cada documento
            for (const doc of pendingDocs) {
                try {
                    // Actualizar estado a INDEXING
                    mysqlConnection.query(
                        'UPDATE chat_pdf_documents SET status = ? WHERE id = ?',
                        ['INDEXING', doc.id],
                        () => { }
                    );

                    const chunksCreated = await indexPdfDocument(doc.s3_key, doc.original_filename, doc.id);

                    // Actualizar estado a INDEXED
                    mysqlConnection.query(
                        'UPDATE chat_pdf_documents SET status = ?, indexed_at = CURRENT_TIMESTAMP WHERE id = ?',
                        ['INDEXED', doc.id],
                        () => { }
                    );

                    successCount++;
                    results.push({
                        id: doc.id,
                        filename: doc.original_filename,
                        status: 'success',
                        chunksCreated: chunksCreated
                    });

                } catch (indexError) {
                    console.error(`❌ Error re-indexando ${doc.original_filename}:`, indexError);

                    // Actualizar estado a ERROR
                    mysqlConnection.query(
                        'UPDATE chat_pdf_documents SET status = ? WHERE id = ?',
                        ['ERROR', doc.id],
                        () => { }
                    );

                    errorCount++;
                    results.push({
                        id: doc.id,
                        filename: doc.original_filename,
                        status: 'error',
                        error: indexError.message
                    });
                }
            }

            res.json({
                success: true,
                message: `Re-indexación completada: ${successCount} exitosos, ${errorCount} con errores`,
                summary: {
                    total: pendingDocs.length,
                    successful: successCount,
                    errors: errorCount
                },
                results: results
            });
        });

    } catch (error) {
        console.error('Error in reindex process:', error);
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor durante la re-indexación'
        });
    }
});

module.exports = router;
