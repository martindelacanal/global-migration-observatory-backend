const express = require('express');
const router = express.Router();

// Import modular route files
const authRoutes = require('./auth');
const categoriesRoutes = require('./categories');
const articlesRoutes = require('./articles');
const summaryRoutes = require('./summary');
const userConfigurationRoutes = require('./userConfiguration');
const chatbotRoutes = require('./chatbot');
const newsletterRoutes = require('./newsletter');

// Use modular routes
router.use('/', authRoutes);
router.use('/', categoriesRoutes);
router.use('/', articlesRoutes);
router.use('/', summaryRoutes);
router.use('/', userConfigurationRoutes);
router.use('/', chatbotRoutes);
router.use('/', newsletterRoutes);

router.get('/ping', (req, res) => {
  res.status(200).send();
});

module.exports = router;
