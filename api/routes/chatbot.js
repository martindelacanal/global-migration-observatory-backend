const express = require('express');
const router = express.Router();
const { GoogleGenAI } = require('@google/genai');
const {
    verifyToken,
    mysqlConnection,
} = require('../utils/sharedHelpers');


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

// POST - Enviar mensaje y obtener respuesta de Gemini
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

                        // Construir contexto para Gemini
                        let conversationContext = '';

                        // Agregar historial previo
                        historyResults.forEach(msg => {
                            conversationContext += `${msg.role === 'user' ? 'Usuario' : 'Asistente'}: ${msg.content}\n`;
                        });

                        // Agregar mensaje actual
                        conversationContext += `Usuario: ${message}\nAsistente:`;

                        // Obtener el prompt personalizado de la base de datos
                        const promptQuery = 'SELECT prompt FROM chat_prompt ORDER BY modification_date DESC LIMIT 1';
                        
                        mysqlConnection.query(promptQuery, [], async (err, promptResults) => {
                            if (err) {
                                console.error('Error getting chat prompt:', err);
                                // Si hay error, usar prompt por defecto
                            }
                            
                            const systemInstruction = promptResults && promptResults.length > 0 && promptResults[0].prompt
                                ? promptResults[0].prompt
                                : "Eres un asistente útil especializado en migración global. Proporciona información precisa y actualizada sobre temas relacionados con migración, políticas migratorias, estadísticas demográficas y tendencias globales.";

                            try {
                                // Llamar a Gemini
                                const response = await ai.models.generateContent({
                                    model: "gemini-2.5-flash",
                                    contents: conversationContext,
                                    config: {
                                        thinkingConfig: {
                                            thinkingBudget: 0, // Disables thinking
                                        },
                                        systemInstruction: systemInstruction,
                                    }
                                });

                                const aiResponse = response.text;

                                // Guardar respuesta de la IA
                                const aiMessageQuery = 'INSERT INTO chat_messages (session_id, role, content) VALUES (?, ?, ?)';

                                mysqlConnection.query(aiMessageQuery, [sessionId, 'assistant', aiResponse], (err, aiMessageResult) => {
                                    if (err) {
                                        console.error('Error saving AI message:', err);
                                        return res.status(500).json({
                                            success: false,
                                            message: 'Error al guardar la respuesta de la IA'
                                        });
                                    }

                                    // Actualizar timestamp de la sesión
                                    const updateSessionQuery = 'UPDATE chat_sessions SET modification_date = CURRENT_TIMESTAMP WHERE id = ?';
                                    mysqlConnection.query(updateSessionQuery, [sessionId], (err) => {
                                        if (err) {
                                            console.error('Error updating session timestamp:', err);
                                        }
                                    });

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

module.exports = router;
