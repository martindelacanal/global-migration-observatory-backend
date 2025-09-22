const express = require('express');
const router = express.Router();
const { mysqlConnection, logger, verifyToken } = require('../utils/sharedHelpers');

// Newsletter subscription endpoint
router.post('/newsletter/subscribe', async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email input
    if (!email) {
      return res.status(400).json({
        message: 'Email is required',
        subscribed: false
      });
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        message: 'Invalid email format',
        subscribed: false
      });
    }

    // Check if email already exists
    const [existingRows] = await mysqlConnection.promise().query(
      'SELECT id, enabled FROM newsletter_subscription WHERE email = ?',
      [email]
    );

    if (existingRows.length > 0) {
      const existingSubscription = existingRows[0];
      
      if (existingSubscription.enabled === 'Y') {
        return res.status(200).json({
          message: 'Email is already subscribed to newsletter',
          subscribed: true
        });
      } else {
        // Re-enable existing subscription
        await mysqlConnection.promise().query(
          'UPDATE newsletter_subscription SET enabled = "Y", modification_date = CURRENT_TIMESTAMP WHERE email = ?',
          [email]
        );
        
        logger.info(`Newsletter subscription re-enabled for email: ${email}`);
        return res.status(200).json({
          message: 'Successfully subscribed to newsletter',
          subscribed: true
        });
      }
    }

    // Insert new subscription
    await mysqlConnection.promise().query(
      'INSERT INTO newsletter_subscription (email, enabled) VALUES (?, "Y")',
      [email]
    );

    logger.info(`New newsletter subscription created for email: ${email}`);
    
    res.status(201).json({
      message: 'Successfully subscribed to newsletter',
      subscribed: true
    });

  } catch (error) {
    console.error('Error subscribing to newsletter:', error);
    logger.error('Error subscribing to newsletter:', error);
    
    res.status(500).json({
      message: 'Internal server error',
      subscribed: false
    });
  }
});

// Admin: Get paginated newsletter subscriptions
router.get('/newsletter/subscriptions', verifyToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    // Validate pagination parameters
    if (page < 1 || limit < 1 || limit > 100) {
      return res.status(400).json({
        message: 'Invalid pagination parameters. Page must be >= 1, limit must be between 1 and 100',
        subscriptions: [],
        total: 0
      });
    }

    // Get total count of subscriptions
    const [countRows] = await mysqlConnection.promise().query(
      'SELECT COUNT(*) as total FROM newsletter_subscription'
    );
    const total = countRows[0].total;

    // Get paginated subscriptions
    const [subscriptionRows] = await mysqlConnection.promise().query(
      `SELECT 
        id,
        email,
        enabled,
        creation_date,
        modification_date
      FROM newsletter_subscription 
      ORDER BY creation_date DESC 
      LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    // Format response according to interface
    const subscriptions = subscriptionRows.map(row => ({
      id: row.id,
      email: row.email,
      enabled: row.enabled,
      creation_date: row.creation_date,
      modification_date: row.modification_date
    }));

    res.status(200).json({
      subscriptions,
      total
    });

  } catch (error) {
    console.error('Error getting newsletter subscriptions:', error);
    logger.error('Error getting newsletter subscriptions:', error);
    
    res.status(500).json({
      message: 'Internal server error',
      subscriptions: [],
      total: 0
    });
  }
});

// Admin: Update subscription status (enable/disable)
router.put('/newsletter/subscriptions/:id/status', verifyToken, async (req, res) => {
  try {
    const subscriptionId = parseInt(req.params.id);
    const { enabled } = req.body;

    // Validate subscription ID
    if (isNaN(subscriptionId) || subscriptionId <= 0) {
      return res.status(400).json({
        message: 'Invalid subscription ID'
      });
    }

    // Validate enabled field
    if (!enabled || (enabled !== 'Y' && enabled !== 'N')) {
      return res.status(400).json({
        message: 'Enabled field must be "Y" or "N"'
      });
    }

    // Check if subscription exists
    const [existingRows] = await mysqlConnection.promise().query(
      'SELECT id, email FROM newsletter_subscription WHERE id = ?',
      [subscriptionId]
    );

    if (existingRows.length === 0) {
      return res.status(404).json({
        message: 'Subscription not found'
      });
    }

    // Update subscription status
    await mysqlConnection.promise().query(
      'UPDATE newsletter_subscription SET enabled = ?, modification_date = CURRENT_TIMESTAMP WHERE id = ?',
      [enabled, subscriptionId]
    );

    const action = enabled === 'Y' ? 'enabled' : 'disabled';
    const email = existingRows[0].email;
    
    logger.info(`Newsletter subscription ${action} for email: ${email} (ID: ${subscriptionId})`);
    
    res.status(200).json({
      message: `Subscription successfully ${action}`
    });

  } catch (error) {
    console.error('Error updating subscription status:', error);
    logger.error('Error updating subscription status:', error);
    
    res.status(500).json({
      message: 'Internal server error'
    });
  }
});

// Admin: Delete a subscription
router.delete('/newsletter/subscriptions/:id', verifyToken, async (req, res) => {
  try {
    const subscriptionId = parseInt(req.params.id);

    // Validate subscription ID
    if (isNaN(subscriptionId) || subscriptionId <= 0) {
      return res.status(400).json({
        message: 'Invalid subscription ID'
      });
    }

    // Check if subscription exists
    const [existingRows] = await mysqlConnection.promise().query(
      'SELECT id, email FROM newsletter_subscription WHERE id = ?',
      [subscriptionId]
    );

    if (existingRows.length === 0) {
      return res.status(404).json({
        message: 'Subscription not found'
      });
    }

    // Delete subscription
    await mysqlConnection.promise().query(
      'DELETE FROM newsletter_subscription WHERE id = ?',
      [subscriptionId]
    );

    const email = existingRows[0].email;
    
    logger.info(`Newsletter subscription deleted for email: ${email} (ID: ${subscriptionId})`);
    
    res.status(200).json({
      message: 'Subscription successfully deleted'
    });

  } catch (error) {
    console.error('Error deleting subscription:', error);
    logger.error('Error deleting subscription:', error);
    
    res.status(500).json({
      message: 'Internal server error'
    });
  }
});

module.exports = router;