const express = require('express');
const router = express.Router();
const { verifyToken, mysqlConnection, logger } = require('../utils/sharedHelpers');

// Get user configuration
router.get('/user-configuration', verifyToken, async (req, res) => {
  try {
    const cabecera = JSON.parse(req.data.data);
    const userId = cabecera.id;

    // Get user configuration from database
    const [rows] = await mysqlConnection.promise().query(
      `SELECT 
        id,
        language,
        notifications_enabled,
        dark_mode,
        auto_save,
        creation_date,
        modification_date
      FROM user 
      WHERE id = ? AND enabled = 'Y'`,
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json('User not found');
    }

    const user = rows[0];

    // Format response according to interface
    const userConfiguration = {
      id: user.id,
      userId: user.id,
      language: user.language || 'en',
      notificationsEnabled: user.notifications_enabled === 'Y',
      darkMode: user.dark_mode === 'Y',
      autoSave: user.auto_save === 'Y',
      createdAt: user.creation_date,
      updatedAt: user.modification_date
    };

    res.status(200).json(userConfiguration);

  } catch (error) {
    console.error('Error getting user configuration:', error);
    logger.error('Error getting user configuration:', error);
    res.status(500).json('Internal server error');
  }
});

// Create user configuration (POST)
router.post('/user-configuration', verifyToken, async (req, res) => {
  try {
    const cabecera = JSON.parse(req.data.data);
    const userId = cabecera.id;
    const { language, notificationsEnabled, darkMode, autoSave } = req.body;

    // Validate required fields
    if (!language || typeof notificationsEnabled !== 'boolean' || 
        typeof darkMode !== 'boolean' || typeof autoSave !== 'boolean') {
      return res.status(400).json('Missing or invalid required fields');
    }

    // Validate language format (should be 'en' or 'es')
    if (!['en', 'es'].includes(language)) {
      return res.status(400).json('Invalid language. Must be "en" or "es"');
    }

    // Convert boolean values to database format
    const notificationsEnabledDb = notificationsEnabled ? 'Y' : 'N';
    const darkModeDb = darkMode ? 'Y' : 'N';
    const autoSaveDb = autoSave ? 'Y' : 'N';

    // Update user configuration in database
    const [result] = await mysqlConnection.promise().query(
      `UPDATE user SET 
        language = ?,
        notifications_enabled = ?,
        dark_mode = ?,
        auto_save = ?,
        modification_date = CURRENT_TIMESTAMP
      WHERE id = ? AND enabled = 'Y'`,
      [language, notificationsEnabledDb, darkModeDb, autoSaveDb, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json('User not found');
    }

    // Get updated user data to return
    const [updatedRows] = await mysqlConnection.promise().query(
      `SELECT 
        id,
        language,
        notifications_enabled,
        dark_mode,
        auto_save,
        creation_date,
        modification_date
      FROM user 
      WHERE id = ?`,
      [userId]
    );

    const updatedUser = updatedRows[0];

    // Format response
    const userConfiguration = {
      id: updatedUser.id,
      userId: updatedUser.id,
      language: updatedUser.language,
      notificationsEnabled: updatedUser.notifications_enabled === 'Y',
      darkMode: updatedUser.dark_mode === 'Y',
      autoSave: updatedUser.auto_save === 'Y',
      createdAt: updatedUser.creation_date,
      updatedAt: updatedUser.modification_date
    };

    res.status(200).json(userConfiguration);

  } catch (error) {
    console.error('Error saving user configuration:', error);
    logger.error('Error saving user configuration:', error);
    res.status(500).json('Internal server error');
  }
});

// Update user configuration (PUT)
router.put('/user-configuration', verifyToken, async (req, res) => {
  try {
    const cabecera = JSON.parse(req.data.data);
    const userId = cabecera.id;
    const { language, notificationsEnabled, darkMode, autoSave } = req.body;

    // Validate required fields
    if (!language || typeof notificationsEnabled !== 'boolean' || 
        typeof darkMode !== 'boolean' || typeof autoSave !== 'boolean') {
      return res.status(400).json('Missing or invalid required fields');
    }

    // Validate language format (should be 'en' or 'es')
    if (!['en', 'es'].includes(language)) {
      return res.status(400).json('Invalid language. Must be "en" or "es"');
    }

    // Convert boolean values to database format
    const notificationsEnabledDb = notificationsEnabled ? 'Y' : 'N';
    const darkModeDb = darkMode ? 'Y' : 'N';
    const autoSaveDb = autoSave ? 'Y' : 'N';

    // Update user configuration in database
    const [result] = await mysqlConnection.promise().query(
      `UPDATE user SET 
        language = ?,
        notifications_enabled = ?,
        dark_mode = ?,
        auto_save = ?,
        modification_date = CURRENT_TIMESTAMP
      WHERE id = ? AND enabled = 'Y'`,
      [language, notificationsEnabledDb, darkModeDb, autoSaveDb, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json('User not found');
    }

    // Get updated user data to return
    const [updatedRows] = await mysqlConnection.promise().query(
      `SELECT 
        id,
        language,
        notifications_enabled,
        dark_mode,
        auto_save,
        creation_date,
        modification_date
      FROM user 
      WHERE id = ?`,
      [userId]
    );

    const updatedUser = updatedRows[0];

    // Format response
    const userConfiguration = {
      id: updatedUser.id,
      userId: updatedUser.id,
      language: updatedUser.language,
      notificationsEnabled: updatedUser.notifications_enabled === 'Y',
      darkMode: updatedUser.dark_mode === 'Y',
      autoSave: updatedUser.auto_save === 'Y',
      createdAt: updatedUser.creation_date,
      updatedAt: updatedUser.modification_date
    };

    res.status(200).json(userConfiguration);

  } catch (error) {
    console.error('Error updating user configuration:', error);
    logger.error('Error updating user configuration:', error);
    res.status(500).json('Internal server error');
  }
});

module.exports = router;
