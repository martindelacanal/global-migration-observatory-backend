const express = require('express');
const router = express.Router();
const { getSignedUrlForImage, getSignedUrlsForImages, mysqlConnection, logger } = require('../utils/sharedHelpers');

// Get opinion articles summary
router.get('/summary/opinion', async (req, res) => {
  try {
    const { language = 'en' } = req.query;

    // Validate language parameter
    if (!['en', 'es'].includes(language)) {
      return res.status(400).json('Invalid language parameter. Must be "en" or "es"');
    }

    // Query opinion articles (category_id = 5) with basic info
    const titleField = language === 'en' ? 'title_en' : 'title_es';
    const subtitleField = language === 'en' ? 'subtitle_en' : 'subtitle_es';
    const slugField = language === 'en' ? 'slug_en' : 'slug_es';

    const query = `
      SELECT 
        ${titleField} as title,
        ${subtitleField} as subtitle,
        ${slugField} as slug,
        author,
        author_gender
      FROM article 
      WHERE category_id = 5 
        AND article_status_id = 2
        AND ${titleField} IS NOT NULL 
        AND ${titleField} != ''
      ORDER BY publication_date DESC, creation_date DESC
      LIMIT 10
    `;

    const [articles] = await mysqlConnection.promise().query(query);

    // Format response to match the frontend interface
    const formattedArticles = articles.map(article => ({
      title: article.title,
      subtitle: article.subtitle || '',
      slug: article.slug,
      author: article.author,
      author_gender: article.author_gender
    }));

    res.json(formattedArticles);

  } catch (error) {
    console.error('Error fetching opinion articles summary:', error);
    logger.error('Error fetching opinion articles summary:', error);
    res.status(500).json('Internal server error');
  }
});

// Get priority articles summary (OPTIMIZED)
router.get('/summary/priority', async (req, res) => {
  try {
    const { language = 'en' } = req.query;

    // Validate language parameter
    if (!['en', 'es'].includes(language)) {
      return res.status(400).json('Invalid language parameter. Must be "en" or "es"');
    }

    // Query priority articles with basic info and preview images
    const titleField = language === 'en' ? 'title_en' : 'title_es';
    const subtitleField = language === 'en' ? 'subtitle_en' : 'subtitle_es';
    const imageType = language === 'en' ? 'preview_en' : 'preview_es';
    const slugField = language === 'en' ? 'slug_en' : 'slug_es';

    const query = `
      SELECT 
        a.priority,
        ${titleField} as title,
        ${subtitleField} as subtitle,
        ${slugField} as slug,
        DATE_FORMAT(CONVERT_TZ(a.publication_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') as date,
        a.author,
        ai.s3_key as image_s3_key
      FROM article a
      LEFT JOIN article_images ai ON a.id = ai.article_id AND ai.image_type = ?
      WHERE a.priority IS NOT NULL 
        AND a.article_status_id = 2
        AND ${titleField} IS NOT NULL 
        AND ${titleField} != ''
      ORDER BY a.priority ASC
    `;

    const [articles] = await mysqlConnection.promise().query(query, [imageType]);

    // Collect all S3 keys for batch processing
    const s3Keys = articles
      .filter(article => article.image_s3_key)
      .map(article => article.image_s3_key);

    // Generate all signed URLs in parallel
    const signedUrls = await getSignedUrlsForImages(s3Keys);
    
    // Create a map for quick lookup
    const urlMap = new Map();
    s3Keys.forEach((key, index) => {
      if (signedUrls[index]) {
        urlMap.set(key, signedUrls[index]);
      }
    });

    // Format response with optimized image URL assignment
    const formattedArticles = articles.map((article) => {
      return {
        priority: article.priority,
        title: article.title,
        subtitle: article.subtitle || undefined,
        slug: article.slug || undefined,
        image: article.image_s3_key ? urlMap.get(article.image_s3_key) : undefined,
        date: article.date,
        author: article.author
      };
    });

    res.json(formattedArticles);

  } catch (error) {
    console.error('Error fetching priority articles summary:', error);
    logger.error('Error fetching priority articles summary:', error);
    res.status(500).json('Internal server error');
  }
});

// Get paginated articles summary (OPTIMIZED)
router.get('/summary/articles', async (req, res) => {
  try {
    const { language = 'en', page = 1, limit = 10, category } = req.query;

    // Validate language parameter
    if (!['en', 'es'].includes(language)) {
      return res.status(400).json('Invalid language parameter. Must be "en" or "es"');
    }

    // Validate pagination parameters
    const pageNumber = parseInt(page);
    const limitNumber = parseInt(limit);
    
    if (isNaN(pageNumber) || pageNumber < 1) {
      return res.status(400).json('Invalid page parameter');
    }
    
    if (isNaN(limitNumber) || limitNumber < 1 || limitNumber > 100) {
      return res.status(400).json('Invalid limit parameter. Must be between 1 and 100');
    }

    // Validate category parameter if provided
    const categoryId = category ? parseInt(category) : null;
    if (category && (isNaN(categoryId) || categoryId < 1)) {
      return res.status(400).json('Invalid category parameter');
    }

    const offset = (pageNumber - 1) * limitNumber;

    // Build count query with optional category filter (OPTIMIZED)
    let countQuery = `SELECT COUNT(*) as total 
       FROM article 
       WHERE article_status_id = 2 
         AND (title_en IS NOT NULL AND title_en != '') 
         AND (title_es IS NOT NULL AND title_es != '')`;
    let countParams = [];

    if (categoryId) {
      countQuery += ' AND category_id = ?';
      countParams.push(categoryId);
    } else {
      countQuery += ' AND category_id != 5';
    }

    // Get total count for pagination
    const [countResult] = await mysqlConnection.promise().query(countQuery, countParams);
    const totalCount = countResult[0].total;

    // Query articles with pagination and preview images (OPTIMIZED)
    const titleField = language === 'en' ? 'title_en' : 'title_es';
    const subtitleField = language === 'en' ? 'subtitle_en' : 'subtitle_es';
    const slugField = language === 'en' ? 'slug_en' : 'slug_es';
    const imageType = language === 'en' ? 'preview_en' : 'preview_es';

    // Build main query with optional category filter
    let query = `
      SELECT 
        ${titleField} as title,
        ${subtitleField} as subtitle,
        ${slugField} as slug,
        DATE_FORMAT(CONVERT_TZ(a.publication_date, '+00:00', 'America/Los_Angeles'), '%Y-%m-%d %T') as publication_date,
        a.author,
        ai.s3_key as image_s3_key
      FROM article a
      LEFT JOIN article_images ai ON a.id = ai.article_id AND ai.image_type = ?
      WHERE a.article_status_id = 2
        AND ${titleField} IS NOT NULL 
        AND ${titleField} != ''
        `;

    let queryParams = [imageType];

    if (!categoryId) {
      query += ' AND a.priority IS NULL';
    }

    if (categoryId) {
      query += ' AND a.category_id = ?';
      queryParams.push(categoryId);
    } else {
      query += ' AND a.category_id != 5';
    }

    query += ' ORDER BY a.publication_date DESC LIMIT ? OFFSET ?';
    queryParams.push(limitNumber, offset);

    const [articles] = await mysqlConnection.promise().query(query, queryParams);

    // Collect all S3 keys for batch processing
    const s3Keys = articles
      .filter(article => article.image_s3_key)
      .map(article => article.image_s3_key);

    // Generate all signed URLs in parallel
    const signedUrls = await getSignedUrlsForImages(s3Keys);
    
    // Create a map for quick lookup
    const urlMap = new Map();
    s3Keys.forEach((key, index) => {
      if (signedUrls[index]) {
        urlMap.set(key, signedUrls[index]);
      }
    });

    // Format response with optimized image URL assignment
    const formattedArticles = articles.map((article) => {
      return {
        title: article.title,
        subtitle: article.subtitle || '',
        author: article.author,
        image: article.image_s3_key ? (urlMap.get(article.image_s3_key) || '') : '',
        publication_date: article.publication_date,
        slug: article.slug
      };
    });

    // Calculate pagination info
    const totalPages = Math.ceil(totalCount / limitNumber);
    const hasNext = pageNumber < totalPages;
    
    const response = {
      articles: formattedArticles,
      totalCount: totalCount,
      currentPage: pageNumber,
      totalPages: totalPages,
      hasNext: hasNext
    };
    res.json(response);

  } catch (error) {
    console.error('Error fetching summary articles:', error);
    logger.error('Error fetching summary articles:', error);
    res.status(500).json('Internal server error');
  }
});

module.exports = router;
