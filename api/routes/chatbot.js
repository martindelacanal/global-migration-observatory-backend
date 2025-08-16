const express = require('express');
const router = express.Router();
const { GoogleGenAI } = require('@google/genai');
const multer = require('multer');
const { ChromaClient } = require('chromadb');
const pdf = require('pdf-parse');
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
        fileSize: 10 * 1024 * 1024 // Límite de 10MB
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

// Configuración de ChromaDB embebido
const chromaClient = new ChromaClient();

const COLLECTION_NAME = 'migration_documents';

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

// Función para obtener la colección de ChromaDB
async function getOrCreateCollection() {
    try {
        return await chromaClient.getOrCreateCollection({
            name: COLLECTION_NAME,
            metadata: { 
                description: "Migration research documents collection",
                created_at: new Date().toISOString()
            }
        });
    } catch (error) {
        console.error('Error getting/creating ChromaDB collection:', error);
        throw error;
    }
}

// Función para indexar un documento PDF
async function indexPdfDocument(s3Key, originalFilename, documentId) {
    try {
        console.log(`Iniciando indexación de documento: ${originalFilename}`);
        
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
        
        // Preparar datos para ChromaDB
        const ids = textChunks.map((_, index) => `${s3Key}-chunk-${index}`);
        const metadatas = textChunks.map((chunk, index) => ({
            source_s3_key: s3Key,
            original_filename: originalFilename,
            document_id: documentId.toString(),
            chunk_index: index,
            chunk_length: chunk.length,
            indexed_at: new Date().toISOString()
        }));
        
        // Agregar documentos a ChromaDB
        await collection.add({
            ids: ids,
            documents: textChunks,
            metadatas: metadatas
        });
        
        console.log(`Documento ${originalFilename} indexado exitosamente. ${textChunks.length} fragmentos creados.`);
        return textChunks.length;
        
    } catch (error) {
        console.error(`Error indexando documento ${originalFilename}:`, error);
        throw error;
    }
}

// Función para eliminar un documento de ChromaDB
async function removeDocumentFromIndex(s3Key) {
    try {
        const collection = await getOrCreateCollection();
        
        // Obtener todos los fragmentos del documento
        const results = await collection.get({
            where: { source_s3_key: s3Key }
        });
        
        if (results.ids.length > 0) {
            // Eliminar todos los fragmentos del documento
            await collection.delete({
                where: { source_s3_key: s3Key }
            });
            
            console.log(`Eliminados ${results.ids.length} fragmentos del documento ${s3Key} de ChromaDB`);
            return results.ids.length;
        }
        
        return 0;
    } catch (error) {
        console.error(`Error eliminando documento ${s3Key} de ChromaDB:`, error);
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


// Inicializar Gemini AI
const ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY
});

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
                            
                            // 1. Buscar documentos relevantes en ChromaDB
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
                                        if (distances[i] < 1.5) { // Filtrar por relevancia (ajustar según necesidad)
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
- Si la pregunta no puede ser respondida con la información del contexto, indica claramente que no tienes esa información en tus documentos.
- NO inventes información que no esté en el contexto.
- Siempre cita o menciona las fuentes cuando sea relevante.
- Si no hay documentos relevantes disponibles, informa al usuario que no tienes información suficiente en la base de conocimiento.

CONTEXTO DE DOCUMENTOS:
${relevantContext}

Pregunta del usuario: ${message}

Responde basándote únicamente en el contexto proporcionado arriba.`;

                                // 4. Construir historial de conversación para mantener contexto
                                let conversationHistory = [];
                                historyResults.forEach(msg => {
                                    conversationHistory.push({
                                        role: msg.role === 'user' ? 'user' : 'model',
                                        parts: [{ text: msg.content }]
                                    });
                                });

                                try {
                                    // 5. Llamar a Gemini con RAG
                                    const chat = ai.getGenerativeModel({ 
                                        model: "gemini-2.5-flash",
                                        systemInstruction: systemInstructionWithRAG
                                    }).startChat({
                                        history: conversationHistory
                                    });
                                    
                                    const result = await chat.sendMessage(message);
                                    const aiResponse = result.response.text();

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

                        // Intentar indexar el documento en ChromaDB
                        try {
                            // Actualizar estado a INDEXING
                            mysqlConnection.query(
                                'UPDATE chat_pdf_documents SET status = ? WHERE id = ?', 
                                ['INDEXING', documentId], 
                                () => {}
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
                                () => {}
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

                // Eliminar de ChromaDB
                try {
                    const deletedChunks = await removeDocumentFromIndex(document.s3_key);
                    console.log(`Eliminados ${deletedChunks} fragmentos de ChromaDB para ${document.original_filename}`);
                } catch (chromaError) {
                    console.error('Error eliminando de ChromaDB (continuando con BD):', chromaError);
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
                        message: `Documento "${document.original_filename}" eliminado exitosamente de S3, ChromaDB y base de datos`
                    });
                });

            } catch (s3Error) {
                console.error('Error deleting from S3:', s3Error);
                
                // Incluso si falla S3, intentar eliminar de ChromaDB y BD
                try {
                    await removeDocumentFromIndex(document.s3_key);
                } catch (chromaError) {
                    console.error('Error eliminando de ChromaDB después de fallo S3:', chromaError);
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
                        message: `Documento "${document.original_filename}" eliminado de la base de datos y ChromaDB (advertencia: posible archivo huérfano en S3)`,
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
                        () => {}
                    );

                    const chunksCreated = await indexPdfDocument(doc.s3_key, doc.original_filename, doc.id);
                    
                    // Actualizar estado a INDEXED
                    mysqlConnection.query(
                        'UPDATE chat_pdf_documents SET status = ?, indexed_at = CURRENT_TIMESTAMP WHERE id = ?', 
                        ['INDEXED', doc.id], 
                        () => {}
                    );

                    successCount++;
                    results.push({
                        id: doc.id,
                        filename: doc.original_filename,
                        status: 'success',
                        chunksCreated: chunksCreated
                    });

                    console.log(`✅ Documento ${doc.original_filename} re-indexado exitosamente`);

                } catch (indexError) {
                    console.error(`❌ Error re-indexando ${doc.original_filename}:`, indexError);
                    
                    // Actualizar estado a ERROR
                    mysqlConnection.query(
                        'UPDATE chat_pdf_documents SET status = ? WHERE id = ?', 
                        ['ERROR', doc.id], 
                        () => {}
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
