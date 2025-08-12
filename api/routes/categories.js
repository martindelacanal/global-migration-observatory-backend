const express = require('express');
const router = express.Router();
const { verifyToken, mysqlConnection } = require('../utils/sharedHelpers');

router.get('/categories', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { lang = 'en' } = req.query; // Idioma por defecto: inglés

      // Consulta SQL que incluye filtrado por idioma si tienes campos multiidioma
      const query = `
      SELECT 
      id,
      ${lang === 'en' ? 'name_en' : 'name_es'} AS name
      FROM category
      ORDER BY name ASC
    `;

      const [rows] = await mysqlConnection.promise().query(query, [lang]);

      if (rows.length > 0) {
        res.status(200).json(rows);
      } else {
        res.status(404).json('categories not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/article/status', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { lang = 'en' } = req.query;

      const query = `
        SELECT 
          id,
          ${lang === 'en' ? 'name_en' : 'name_es'} AS name
        FROM article_status
        ORDER BY name ASC
      `;

      const [rows] = await mysqlConnection.promise().query(query);

      if (rows.length > 0) {
        res.status(200).json(rows);
      } else {
        res.status(404).json('article status not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

module.exports = router;
