const express = require('express');
const router = express.Router();
const multer = require('multer');
const { 
  verifyToken, 
  getSignedUrlForImage, 
  getSignedUrlsForImages,
  s3, 
  bucketName, 
  randomImageName, 
  PutObjectCommand, 
  DeleteObjectsCommand,
  crypto, 
  mysqlConnection, 
  logger 
} = require('../utils/sharedHelpers');

const storage = multer.memoryStorage();

// Multer configuration for article images
const articleUpload = multer({ storage: storage }).fields([
  { name: 'imageEnglish', maxCount: 1 },
  { name: 'imageSpanish', maxCount: 1 },
  { name: 'image', maxCount: 1 } // For content images
]);

// Helper function to generate slug from title
function generateSlug(title) {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '') // Remove special characters
    .replace(/\s+/g, '-') // Replace spaces with hyphens
    .replace(/-+/g, '-') // Replace multiple hyphens with single
    .trim()
    .substring(0, 100); // Limit length
}

// Helper function to calculate file hash
function calculateFileHash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Helper function to extract base64 images from HTML content
function extractBase64Images(htmlContent) {
  const base64Regex = /<img[^>]+src="data:image\/([^;]+);base64,([^"]+)"[^>]*>/g;
  const images = [];
  let match;

  while ((match = base64Regex.exec(htmlContent)) !== null) {
    const fullMatch = match[0];
    const imageFormat = match[1]; // jpeg, png, etc.
    const base64Data = match[2];
    
    // Extract alt text if present
    const altMatch = fullMatch.match(/alt="([^"]*)"/);
    const altText = altMatch ? altMatch[1] : '';

    images.push({
      fullMatch,
      imageFormat,
      base64Data,
      altText,
      mimeType: `image/${imageFormat}`
    });
  }

  return images;
}

// Helper function to upload content images and replace base64 with S3 keys
async function processContentImages(htmlContent, articleId, language = 'en') {
  try {
    const base64Images = extractBase64Images(htmlContent);
    let processedContent = htmlContent;
    let displayOrder = 1;

    for (const imageData of base64Images) {
      try {
        // Convert base64 to buffer
        const imageBuffer = Buffer.from(imageData.base64Data, 'base64');
        const fileHash = calculateFileHash(imageBuffer);
        
        // Check if image already exists for this article
        const [existingImage] = await mysqlConnection.promise().query(
          'SELECT s3_key FROM article_images WHERE article_id = ? AND file_hash = ? AND image_type = "content"',
          [articleId, fileHash]
        );

        let s3Key;
        
        if (existingImage.length > 0) {
          // Image already exists, use existing S3 key
          s3Key = existingImage[0].s3_key;
        } else {
          // Upload new image
          s3Key = randomImageName();
          
          const uploadParams = {
            Bucket: bucketName,
            Key: s3Key,
            Body: imageBuffer,
            ContentType: imageData.mimeType,
          };
          
          const command = new PutObjectCommand(uploadParams);
          await s3.send(command);

          // Save image info to database
          await mysqlConnection.promise().query(
            `INSERT INTO article_images (
              article_id, image_type, s3_key, s3_bucket, file_hash, 
              original_filename, mime_type, file_size, alt_text_${language}, 
              display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              articleId, 'content', s3Key, bucketName, fileHash,
              `content_image_${displayOrder}.${imageData.imageFormat}`, 
              imageData.mimeType, imageBuffer.length, imageData.altText,
              displayOrder++
            ]
          );
        }

        // Replace base64 image with S3 key placeholder in content
        // Use a special format that we can identify and replace later
        const newImgTag = imageData.fullMatch.replace(
          /src="data:image\/[^;]+;base64,[^"]+"/,
          `src="{{S3_KEY:${s3Key}}}"`
        );
        
        processedContent = processedContent.replace(imageData.fullMatch, newImgTag);

      } catch (imageError) {
        logger.error(`Error processing individual image: ${imageError.message}`);
        // Continue with other images even if one fails
      }
    }

    return processedContent;

  } catch (error) {
    logger.error('Error processing content images:', error);
    throw error;
  }
}

function decodeHtmlAmpersands(value) {
  return String(value || '')
    .replace(/&amp;/gi, '&')
    .replace(/&#38;/gi, '&');
}

function extractS3KeyFromUrl(urlValue) {
  try {
    if (!urlValue || !bucketName) return null;

    const normalizedUrl = decodeHtmlAmpersands(urlValue);
    const parsedUrl = new URL(normalizedUrl);
    const host = parsedUrl.hostname.toLowerCase();
    const bucket = String(bucketName).toLowerCase();
    const path = parsedUrl.pathname || '';

    if (!path || path === '/') return null;

    // Virtual-hosted style:
    // https://{bucket}.s3.{region}.amazonaws.com/{key}
    const virtualHostPrefix = `${bucket}.s3`;
    if (host.startsWith(virtualHostPrefix) && host.endsWith('.amazonaws.com')) {
      const key = decodeURIComponent(path.slice(1));
      return key || null;
    }

    // Path-style:
    // https://s3.{region}.amazonaws.com/{bucket}/{key}
    if (
      (host === 's3.amazonaws.com' || (host.startsWith('s3.') && host.endsWith('.amazonaws.com'))) &&
      path.toLowerCase().startsWith(`/${bucket}/`)
    ) {
      const key = decodeURIComponent(path.slice(bucket.length + 2));
      return key || null;
    }

    return null;
  } catch (_) {
    return null;
  }
}

// Helper function to convert S3 URLs back to placeholders
function convertS3UrlsToPlaceholders(content) {
  try {
    if (typeof content !== 'string' || content.length === 0) {
      return content;
    }

    const s3UrlRegex = /https:\/\/[^"'\s<]+/gi;
    let processedContent = content;
    let match;

    while ((match = s3UrlRegex.exec(content)) !== null) {
      const fullUrl = match[0];
      const s3Key = extractS3KeyFromUrl(fullUrl);

      if (s3Key) {
        const placeholder = `{{S3_KEY:${s3Key}}}`;
        processedContent = processedContent.replace(fullUrl, placeholder);
      }
    }

    return processedContent;
  } catch (error) {
    logger.error('Error converting S3 URLs to placeholders:', error);
    return content; // Return original content if processing fails
  }
}

// Helper function to cleanup orphaned content images
async function cleanupOrphanedContentImages(articleId, newContentEn, newContentEs) {
  try {
    // Get all current content images for this article
    const [currentImages] = await mysqlConnection.promise().query(
      'SELECT id, s3_key FROM article_images WHERE article_id = ? AND image_type = "content"',
      [articleId]
    );

    const imagesToDelete = [];

    for (const image of currentImages) {
      const s3KeyPlaceholder = `{{S3_KEY:${image.s3_key}}}`;
      
      // Check if S3 key is still present in either content
      const stillUsedInEn = newContentEn.includes(s3KeyPlaceholder);
      const stillUsedInEs = newContentEs.includes(s3KeyPlaceholder);

      if (!stillUsedInEn && !stillUsedInEs) {
        imagesToDelete.push(image);
      }
    }

    // Delete orphaned images from S3 and database
    if (imagesToDelete.length > 0) {
      // Delete from S3
      const deleteParams = {
        Bucket: bucketName,
        Delete: {
          Objects: imagesToDelete.map(img => ({ Key: img.s3_key })),
          Quiet: false,
        },
      };

      const deleteCommand = new DeleteObjectsCommand(deleteParams);
      await s3.send(deleteCommand);

      // Delete from database
      const imageIds = imagesToDelete.map(img => img.id);
      await mysqlConnection.promise().query(
        `DELETE FROM article_images WHERE id IN (${imageIds.map(() => '?').join(',')})`,
        imageIds
      );

    }

  } catch (error) {
    logger.error('Error cleaning up orphaned images:', error);
    // Don't throw error as this is cleanup operation
  }
}

// Helper function to replace S3 key placeholders with signed URLs in content (OPTIMIZED)
async function replaceS3KeysWithSignedUrls(content) {
  try {
    if (typeof content !== 'string' || content.length === 0) {
      return content;
    }

    // Refresh legacy/expired S3 URLs by converting them to placeholders first.
    const normalizedContent = convertS3UrlsToPlaceholders(content);

    // Find all S3 key placeholders in the format {{S3_KEY:filename}}
    const s3KeyRegex = /\{\{S3_KEY:([^}]+)\}\}/g;
    const matches = [];
    let match;

    // Collect all S3 keys first
    while ((match = s3KeyRegex.exec(normalizedContent)) !== null) {
      matches.push({
        placeholder: match[0],
        s3Key: match[1]
      });
    }

    if (matches.length === 0) {
      return normalizedContent;
    }

    // Generate all signed URLs in parallel
    const s3Keys = matches.map(m => m.s3Key);
    const signedUrls = await getSignedUrlsForImages(s3Keys);
    
    let modifiedContent = normalizedContent;

    // Replace all placeholders with their corresponding signed URLs
    matches.forEach((matchData, index) => {
      const signedUrl = signedUrls[index];
      if (signedUrl) {
        modifiedContent = modifiedContent.replace(matchData.placeholder, signedUrl);
      } else {
        // If we can't generate signed URL, remove the image tag
        logger.warn(`Could not generate signed URL for ${matchData.s3Key}, removing image`);
        modifiedContent = modifiedContent.replace(
          new RegExp(`<img[^>]*src="${matchData.placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"[^>]*>`, 'g'),
          ''
        );
      }
    });

    return modifiedContent;
  } catch (error) {
    logger.error('Error replacing S3 keys with signed URLs:', error);
    return content; // Return original content if processing fails
  }
}

const MIN_ARTICLE_PRIORITY = 1;
const MAX_ARTICLE_PRIORITY = 8;

// Helper function to manage article priorities (1-8, unique values)
async function managePriority(newPriority, excludeArticleId = null) {
  const priority = Number.parseInt(newPriority, 10);

  if (!Number.isInteger(priority) || priority < MIN_ARTICLE_PRIORITY || priority > MAX_ARTICLE_PRIORITY) {
    return null;
  }

  const connection = await mysqlConnection.promise().getConnection();

  try {
    await connection.beginTransaction();

    // Get the current priority of the article being updated (if any)
    let currentPriority = null;
    if (excludeArticleId) {
      const [currentArticle] = await connection.query(
        'SELECT priority FROM article WHERE id = ? FOR UPDATE',
        [excludeArticleId]
      );
      if (currentArticle.length > 0) {
        currentPriority = currentArticle[0].priority;
      }
    }

    // Nothing to do if an existing article keeps the same priority
    if (currentPriority === priority) {
      await connection.commit();
      return priority;
    }

    // Check if the target priority is already used by another article
    let existingQuery = 'SELECT id FROM article WHERE priority = ?';
    const existingParams = [priority];

    if (excludeArticleId) {
      existingQuery += ' AND id != ?';
      existingParams.push(excludeArticleId);
    }

    existingQuery += ' FOR UPDATE';
    const [existingArticle] = await connection.query(existingQuery, existingParams);

    if (existingArticle.length > 0) {
      // Case 1: Creating new article or article without previous priority
      if (!excludeArticleId || currentPriority === null) {
        const shiftParams = [MAX_ARTICLE_PRIORITY, priority];
        let shiftQuery = `
          UPDATE article
          SET priority = CASE
            WHEN priority = ? THEN NULL
            ELSE priority + 1
          END
          WHERE priority >= ? AND priority IS NOT NULL
        `;

        if (excludeArticleId) {
          shiftQuery += ' AND id != ?';
          shiftParams.push(excludeArticleId);
        }

        await connection.query(shiftQuery, shiftParams);
      }
      // Case 2: Article is moving from one priority to another
      else if (currentPriority < priority) {
        // Moving down: shift articles between currentPriority+1 and newPriority up
        await connection.query(
          'UPDATE article SET priority = priority - 1 WHERE priority > ? AND priority <= ? AND id != ?',
          [currentPriority, priority, excludeArticleId]
        );
      } else if (currentPriority > priority) {
        // Moving up: shift articles between newPriority and currentPriority-1 down
        await connection.query(
          'UPDATE article SET priority = priority + 1 WHERE priority >= ? AND priority < ? AND id != ?',
          [priority, currentPriority, excludeArticleId]
        );
      }
    }

    await connection.commit();
    return priority;
  } catch (error) {
    try {
      await connection.rollback();
    } catch (rollbackError) {
      logger.error('Error rolling back priority transaction:', rollbackError);
    }
    logger.error('Error managing article priority:', error);
    throw error;
  } finally {
    connection.release();
  }
}

// Helper function to upload image to S3 and save to database
async function uploadArticleImage(file, articleId, imageType, altTextEn = '', altTextEs = '', captionEn = '', captionEs = '') {
  try {
    const fileHash = calculateFileHash(file.buffer);
    const fileName = randomImageName();
    
    // Upload to S3
    const uploadParams = {
      Bucket: bucketName,
      Key: fileName,
      Body: file.buffer,
      ContentType: file.mimetype,
    };
    
    const command = new PutObjectCommand(uploadParams);
    await s3.send(command);
    
    // Save to database
    const [result] = await mysqlConnection.promise().query(
      `INSERT INTO article_images (
        article_id, image_type, s3_key, s3_bucket, file_hash, 
        original_filename, mime_type, file_size, alt_text_en, 
        alt_text_es, caption_en, caption_es
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        articleId, imageType, fileName, bucketName, fileHash,
        file.originalname, file.mimetype, file.size, altTextEn,
        altTextEs, captionEn, captionEs
      ]
    );
    
    return {
      id: result.insertId,
      s3_key: fileName
    };
  } catch (error) {
    logger.error('Error uploading article image:', error);
    throw error;
  }
}

// Create article
router.post('/article', verifyToken, articleUpload, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  
  if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
    return res.status(401).json('Unauthorized');
  }

  try {
    const {
      titleEnglish, titleSpanish, subtitleEnglish, subtitleSpanish,
      contentEnglish, contentSpanish, author, author_gender, date, categoryId,
      article_status_id, priority, imageCaptionEnglish, imageCaptionSpanish
    } = req.body;

    // Generate slugs
    const slugEn = generateSlug(titleEnglish);
    const slugEs = generateSlug(titleSpanish);

    // Format publication date
    const publicationDate = new Date(date).toISOString().slice(0, 19).replace('T', ' ');

    // Manage priority (ensure uniqueness and shift if necessary)
    const managedPriority = await managePriority(priority);

    // Insert article first to get ID
    const [articleResult] = await mysqlConnection.promise().query(
      `INSERT INTO article (
        title_en, title_es, subtitle_en, subtitle_es, content_en, content_es,
        author, author_gender, publication_date, category_id, priority, article_status_id,
        slug_en, slug_es
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        titleEnglish, titleSpanish, subtitleEnglish || null, subtitleSpanish || null,
        contentEnglish, contentSpanish, author, author_gender, publicationDate, categoryId,
        managedPriority, article_status_id || 1, slugEn, slugEs
      ]
    );

    const articleId = articleResult.insertId;

    // Process content images (convert base64 to S3 URLs)
    let processedContentEnglish = contentEnglish;
    let processedContentSpanish = contentSpanish;

    try {
      processedContentEnglish = await processContentImages(contentEnglish, articleId, 'en');
      processedContentSpanish = await processContentImages(contentSpanish, articleId, 'es');

      // Update article with processed content (only if images were processed)
      if (processedContentEnglish !== contentEnglish || processedContentSpanish !== contentSpanish) {
        await mysqlConnection.promise().query(
          'UPDATE article SET content_en = ?, content_es = ? WHERE id = ?',
          [processedContentEnglish, processedContentSpanish, articleId]
        );
      }
    } catch (contentImageError) {
      logger.error('Error processing content images:', contentImageError);
      // Continue with article creation even if image processing fails
    }

    let imageEnglishUrl = null;
    let imageSpanishUrl = null;
    // Upload preview images if provided
    if (req.files?.imageEnglish) {
      try {
        // Delete existing English preview image if any
        await mysqlConnection.promise().query(
          'DELETE FROM article_images WHERE article_id = ? AND image_type = "preview_en"',
          [articleId]
        );
        
        const uploadResult = await uploadArticleImage(
          req.files.imageEnglish[0], 
          articleId, 
          'preview_en', 
          '', 
          '', 
          imageCaptionEnglish || '', 
          ''
        );
        imageEnglishUrl = await getSignedUrlForImage(uploadResult.s3_key);
      } catch (previewImageError) {
        logger.error('Error uploading English preview image:', previewImageError);
      }
    }

    if (req.files?.imageSpanish) {
      console.log(req.files.imageSpanish[0]);
      try {
        // Delete existing Spanish preview image if any
        await mysqlConnection.promise().query(
          'DELETE FROM article_images WHERE article_id = ? AND image_type = "preview_es"',
          [articleId]
        );
        
        const uploadResult = await uploadArticleImage(
          req.files.imageSpanish[0], 
          articleId, 
          'preview_es', 
          '', 
          '', 
          '', 
          imageCaptionSpanish || ''
        );
        imageSpanishUrl = await getSignedUrlForImage(uploadResult.s3_key);
      } catch (previewImageError) {
        logger.error('Error uploading Spanish preview image:', previewImageError);
      }
    }

    // Replace S3 key placeholders with signed URLs in content for response
    const contentEnglishWithUrls = await replaceS3KeysWithSignedUrls(processedContentEnglish);
    const contentSpanishWithUrls = await replaceS3KeysWithSignedUrls(processedContentSpanish);

    // Return created article with processed content
    const response = {
      id: articleId,
      titleEnglish,
      titleSpanish,
      subtitleEnglish: subtitleEnglish || null,
      subtitleSpanish: subtitleSpanish || null,
      contentEnglish: contentEnglishWithUrls,
      contentSpanish: contentSpanishWithUrls,
      author,
      author_gender,
      date: publicationDate,
      categoryId: parseInt(categoryId),
      priority: managedPriority,
      article_status_id: parseInt(article_status_id) || 1,
      imageEnglishUrl,
      imageSpanishUrl,
      imageCaptionEnglish: imageCaptionEnglish || null,
      imageCaptionSpanish: imageCaptionSpanish || null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    res.status(201).json(response);

  } catch (error) {
    console.error('Error creating article:', error);
    logger.error('Error creating article:', error);
    res.status(500).json('Internal server error');
  }
});

// Get articles with pagination (OPTIMIZED - no content, only preview data)
router.get('/article', async (req, res) => {
  try {
    const { page = 1, limit = 10, lang = 'en' } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Get total count with optimized query
    const [countResult] = await mysqlConnection.promise().query(
      'SELECT COUNT(*) as total FROM article WHERE article_status_id = 2'
    );
    const total = countResult[0].total;

    // Optimized query - only essential fields, no heavy content
    const query = `
      SELECT 
        a.id,
        a.title_en as titleEnglish,
        a.title_es as titleSpanish,
        a.subtitle_en as subtitleEnglish,
        a.subtitle_es as subtitleSpanish,
        a.author,
        a.author_gender,
        DATE_FORMAT(CONVERT_TZ(a.publication_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as date,
        a.category_id as categoryId,
        a.priority,
        a.article_status_id,
        a.slug_en as slugEnglish,
        a.slug_es as slugSpanish,
        a.view_count,
        a.featured,
        DATE_FORMAT(CONVERT_TZ(a.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as createdAt,
        DATE_FORMAT(CONVERT_TZ(a.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as updatedAt,
        c.name_en as categoryNameEnglish,
        c.name_es as categoryNameSpanish,
        asi.name_en as statusNameEnglish,
        asi.name_es as statusNameSpanish,
        GROUP_CONCAT(
          CASE 
            WHEN ai.image_type = 'preview_en' THEN ai.s3_key
            ELSE NULL
          END
        ) as previewEnglishKey,
        GROUP_CONCAT(
          CASE 
            WHEN ai.image_type = 'preview_es' THEN ai.s3_key
            ELSE NULL
          END
        ) as previewSpanishKey,
        GROUP_CONCAT(
          CASE 
            WHEN ai.image_type = 'preview_en' THEN ai.caption_en
            ELSE NULL
          END
        ) as imageCaptionEnglish,
        GROUP_CONCAT(
          CASE 
            WHEN ai.image_type = 'preview_es' THEN ai.caption_es
            ELSE NULL
          END
        ) as imageCaptionSpanish
      FROM article a
      LEFT JOIN category c ON a.category_id = c.id
      LEFT JOIN article_status asi ON a.article_status_id = asi.id
      LEFT JOIN article_images ai ON a.id = ai.article_id AND ai.image_type IN ('preview_en', 'preview_es')
      GROUP BY a.id
      ORDER BY a.publication_date DESC, a.creation_date DESC
      LIMIT ? OFFSET ?
    `;

    const [articles] = await mysqlConnection.promise().query(query, [parseInt(limit), offset]);

    // Collect all S3 keys for batch processing
    const s3Keys = [];
    const keyMap = new Map();
    
    articles.forEach((article, index) => {
      if (article.previewEnglishKey) {
        s3Keys.push(article.previewEnglishKey);
        keyMap.set(article.previewEnglishKey, { articleIndex: index, type: 'english' });
      }
      if (article.previewSpanishKey) {
        s3Keys.push(article.previewSpanishKey);
        keyMap.set(article.previewSpanishKey, { articleIndex: index, type: 'spanish' });
      }
    });

    // Generate all signed URLs in parallel
    const signedUrls = await getSignedUrlsForImages(s3Keys);
    
    // Map signed URLs back to articles
    const urlMap = new Map();
    s3Keys.forEach((key, index) => {
      if (signedUrls[index]) {
        urlMap.set(key, signedUrls[index]);
      }
    });

    // Format response with optimized image URL assignment
    const formattedArticles = articles.map((article) => {
      return {
        id: article.id,
        titleEnglish: article.titleEnglish,
        titleSpanish: article.titleSpanish,
        subtitleEnglish: article.subtitleEnglish,
        subtitleSpanish: article.subtitleSpanish,
        // No content fields - these will be fetched separately when needed
        author: article.author,
        author_gender: article.author_gender,
        date: article.date,
        categoryId: article.categoryId,
        categoryNameEnglish: article.categoryNameEnglish,
        categoryNameSpanish: article.categoryNameSpanish,
        priority: article.priority,
        article_status_id: article.article_status_id,
        statusNameEnglish: article.statusNameEnglish,
        statusNameSpanish: article.statusNameSpanish,
        slugEnglish: article.slugEnglish,
        slugSpanish: article.slugSpanish,
        viewCount: article.view_count,
        featured: article.featured,
        imageEnglishUrl: article.previewEnglishKey ? urlMap.get(article.previewEnglishKey) : null,
        imageSpanishUrl: article.previewSpanishKey ? urlMap.get(article.previewSpanishKey) : null,
        imageCaptionEnglish: article.imageCaptionEnglish,
        imageCaptionSpanish: article.imageCaptionSpanish,
        createdAt: article.createdAt,
        updatedAt: article.updatedAt
      };
    });

    res.json({
      articles: formattedArticles,
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(total / parseInt(limit))
    });

  } catch (error) {
    console.error('Error fetching articles:', error);
    logger.error('Error fetching articles:', error);
    res.status(500).json('Internal server error');
  }
});

// Get article content by ID (separate endpoint for heavy content)
router.get('/article/:id/content', async (req, res) => {
  try {
    const { id } = req.params;
    const { lang = 'en' } = req.query;

    // Get only content fields
    const [articles] = await mysqlConnection.promise().query(
      `SELECT content_en, content_es FROM article WHERE id = ? AND article_status_id = 2`,
      [id]
    );

    if (articles.length === 0) {
      return res.status(404).json('Article not found');
    }

    const article = articles[0];

    // Replace S3 key placeholders with signed URLs in content
    const contentEnglishWithUrls = await replaceS3KeysWithSignedUrls(article.content_en);
    const contentSpanishWithUrls = await replaceS3KeysWithSignedUrls(article.content_es);

    const response = {
      contentEnglish: contentEnglishWithUrls,
      contentSpanish: contentSpanishWithUrls
    };

    res.json(response);

  } catch (error) {
    console.error('Error fetching article content:', error);
    logger.error('Error fetching article content:', error);
    res.status(500).json('Internal server error');
  }
});

// Get article by ID
router.get('/article/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { lang = 'en' } = req.query;

    // Get article with images
    const [articles] = await mysqlConnection.promise().query(
      `SELECT 
        a.*,
        DATE_FORMAT(CONVERT_TZ(a.publication_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as date,
        c.name_${lang === 'en' ? 'en' : 'es'} as categoryName,
        asi.name_${lang === 'en' ? 'en' : 'es'} as statusName
      FROM article a
      LEFT JOIN category c ON a.category_id = c.id
      LEFT JOIN article_status asi ON a.article_status_id = asi.id
      WHERE a.id = ?`,
      [id]
    );

    if (articles.length === 0) {
      return res.status(404).json('Article not found');
    }

    const article = articles[0];

    // Get article images
    const [images] = await mysqlConnection.promise().query(
      `SELECT 
        image_type,
        s3_key,
        alt_text_en,
        alt_text_es,
        caption_en,
        caption_es
      FROM article_images 
      WHERE article_id = ?
      ORDER BY image_type, display_order`,
      [id]
    );

    // Format images with signed URLs
    let imageEnglishUrl = null;
    let imageSpanishUrl = null;
    let imageCaptionEnglish = null;
    let imageCaptionSpanish = null;

    for (const img of images) {
      if (img.image_type === 'preview_en') {
        imageEnglishUrl = await getSignedUrlForImage(img.s3_key);
        imageCaptionEnglish = img.caption_en;
      } else if (img.image_type === 'preview_es') {
        imageSpanishUrl = await getSignedUrlForImage(img.s3_key);
        imageCaptionSpanish = img.caption_es;
      }
    }

    // Replace S3 key placeholders with signed URLs in content
    const contentEnglishWithUrls = await replaceS3KeysWithSignedUrls(article.content_en);
    const contentSpanishWithUrls = await replaceS3KeysWithSignedUrls(article.content_es);

    // Update view count
    await mysqlConnection.promise().query(
      'UPDATE article SET view_count = view_count + 1 WHERE id = ?',
      [id]
    );

    const response = {
      id: article.id,
      titleEnglish: article.title_en,
      titleSpanish: article.title_es,
      subtitleEnglish: article.subtitle_en,
      subtitleSpanish: article.subtitle_es,
      contentEnglish: contentEnglishWithUrls,
      contentSpanish: contentSpanishWithUrls,
      author: article.author,
      author_gender: article.author_gender,
      date: article.date,
      categoryId: article.category_id,
      categoryName: article.categoryName,
      priority: article.priority,
      article_status_id: article.article_status_id,
      statusName: article.statusName,
      slugEnglish: article.slug_en,
      slugSpanish: article.slug_es,
      viewCount: article.view_count + 1,
      featured: article.featured,
      imageEnglishUrl,
      imageSpanishUrl,
      imageCaptionEnglish,
      imageCaptionSpanish,
      createdAt: article.creation_date,
      updatedAt: article.modification_date
    };
    
    res.json(response);

  } catch (error) {
    console.error('Error fetching article:', error);
    logger.error('Error fetching article:', error);
    res.status(500).json('Internal server error');
  }
});

// Get article by slug
router.get('/article/slug/:slug', async (req, res) => {
  try {
    const { slug } = req.params;
    let matchedLanguage = null;
    let article = null;

    // First, try to find by English slug
    const [englishArticles] = await mysqlConnection.promise().query(
      `SELECT 
        a.*,
        DATE_FORMAT(CONVERT_TZ(a.publication_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as date,
        c.name_en as categoryNameEn,
        c.name_es as categoryNameEs,
        asi.name_en as statusNameEn,
        asi.name_es as statusNameEs
      FROM article a
      LEFT JOIN category c ON a.category_id = c.id
      LEFT JOIN article_status asi ON a.article_status_id = asi.id
      WHERE a.slug_en = ?`,
      [slug]
    );

    if (englishArticles.length > 0) {
      article = englishArticles[0];
      matchedLanguage = 'en';
    } else {
      // If not found by English slug, try Spanish slug
      const [spanishArticles] = await mysqlConnection.promise().query(
        `SELECT 
          a.*,
          DATE_FORMAT(CONVERT_TZ(a.publication_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as date,
          c.name_en as categoryNameEn,
          c.name_es as categoryNameEs,
          asi.name_en as statusNameEn,
          asi.name_es as statusNameEs
        FROM article a
        LEFT JOIN category c ON a.category_id = c.id
        LEFT JOIN article_status asi ON a.article_status_id = asi.id
        WHERE a.slug_es = ?`,
        [slug]
      );

      if (spanishArticles.length > 0) {
        article = spanishArticles[0];
        matchedLanguage = 'es';
      }
    }

    // If no article found with either slug, return 404
    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    // Get article images
    const [images] = await mysqlConnection.promise().query(
      `SELECT 
        image_type,
        s3_key,
        alt_text_en,
        alt_text_es,
        caption_en,
        caption_es
      FROM article_images 
      WHERE article_id = ?
      ORDER BY image_type, display_order`,
      [article.id]
    );

    // Format images with signed URLs
    let imageEnglishUrl = null;
    let imageSpanishUrl = null;
    let imageCaptionEnglish = null;
    let imageCaptionSpanish = null;

    for (const img of images) {
      if (img.image_type === 'preview_en') {
        imageEnglishUrl = await getSignedUrlForImage(img.s3_key);
        imageCaptionEnglish = img.caption_en;
      } else if (img.image_type === 'preview_es') {
        imageSpanishUrl = await getSignedUrlForImage(img.s3_key);
        imageCaptionSpanish = img.caption_es;
      }
    }

    // Replace S3 key placeholders with signed URLs in content
    const contentEnglishWithUrls = await replaceS3KeysWithSignedUrls(article.content_en);
    const contentSpanishWithUrls = await replaceS3KeysWithSignedUrls(article.content_es);

    // Update view count
    await mysqlConnection.promise().query(
      'UPDATE article SET view_count = view_count + 1 WHERE id = ?',
      [article.id]
    );

    const articleResponse = {
      id: article.id,
      titleEnglish: article.title_en,
      titleSpanish: article.title_es,
      subtitleEnglish: article.subtitle_en,
      subtitleSpanish: article.subtitle_es,
      contentEnglish: contentEnglishWithUrls,
      contentSpanish: contentSpanishWithUrls,
      author: article.author,
      author_gender: article.author_gender,
      date: article.date,
      categoryId: article.category_id,
      categoryNameEnglish: article.categoryNameEn,
      categoryNameSpanish: article.categoryNameEs,
      priority: article.priority,
      article_status_id: article.article_status_id,
      statusNameEnglish: article.statusNameEn,
      statusNameSpanish: article.statusNameEs,
      slugEnglish: article.slug_en,
      slugSpanish: article.slug_es,
      viewCount: article.view_count + 1,
      featured: article.featured,
      imageEnglishUrl,
      imageSpanishUrl,
      imageCaptionEnglish,
      imageCaptionSpanish,
      createdAt: article.creation_date,
      updatedAt: article.modification_date
    };

    const response = {
      article: articleResponse,
      matchedLanguage
    };

    res.json(response);

  } catch (error) {
    console.error('Error fetching article by slug:', error);
    logger.error('Error fetching article by slug:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update article
router.put('/article/:id', verifyToken, articleUpload, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  
  if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
    return res.status(401).json('Unauthorized');
  }

  try {
    const { id } = req.params;
    const {
      titleEnglish, titleSpanish, subtitleEnglish, subtitleSpanish,
      contentEnglish, contentSpanish, author, author_gender, date, categoryId,
      article_status_id, priority, imageCaptionEnglish, imageCaptionSpanish
    } = req.body;

    // Check if article exists
    const [existingArticle] = await mysqlConnection.promise().query(
      'SELECT id FROM article WHERE id = ?',
      [id]
    );

    if (existingArticle.length === 0) {
      return res.status(404).json('Article not found');
    }

    // Generate new slugs if titles changed
    const slugEn = generateSlug(titleEnglish);
    const slugEs = generateSlug(titleSpanish);

    // Format publication date
    const publicationDate = new Date(date).toISOString().slice(0, 19).replace('T', ' ');

    // Manage priority (ensure uniqueness and shift if necessary, excluding current article)
    const managedPriority = await managePriority(priority, id);

    // Convert S3 URLs back to placeholders before processing
    const contentEnglishWithPlaceholders = convertS3UrlsToPlaceholders(contentEnglish);
    const contentSpanishWithPlaceholders = convertS3UrlsToPlaceholders(contentSpanish);

    // Process content images (convert base64 to S3 URLs)
    let processedContentEnglish = contentEnglishWithPlaceholders;
    let processedContentSpanish = contentSpanishWithPlaceholders;

    try {
      processedContentEnglish = await processContentImages(contentEnglishWithPlaceholders, id, 'en');
      processedContentSpanish = await processContentImages(contentSpanishWithPlaceholders, id, 'es');

      // Clean up orphaned content images
      await cleanupOrphanedContentImages(id, processedContentEnglish, processedContentSpanish);

    } catch (contentImageError) {
      logger.error('Error processing content images during update:', contentImageError);
      // Continue with article update even if image processing fails
    }

    // Update article with processed content
    await mysqlConnection.promise().query(
      `UPDATE article SET 
        title_en = ?, title_es = ?, subtitle_en = ?, subtitle_es = ?,
        content_en = ?, content_es = ?, author = ?, author_gender = ?, publication_date = ?,
        category_id = ?, priority = ?, article_status_id = ?,
        slug_en = ?, slug_es = ?, modification_date = CURRENT_TIMESTAMP
      WHERE id = ?`,
      [
        titleEnglish, titleSpanish, subtitleEnglish || null, subtitleSpanish || null,
        processedContentEnglish, processedContentSpanish, author, author_gender, publicationDate, categoryId,
        managedPriority, article_status_id || 1, slugEn, slugEs, id
      ]
    );

    let imageEnglishUrl = null;
    let imageSpanishUrl = null;

    // Handle new preview images
    if (req.files?.imageEnglish) {
      try {
        // Delete existing English preview image if any
        await mysqlConnection.promise().query(
          'DELETE FROM article_images WHERE article_id = ? AND image_type = "preview_en"',
          [id]
        );
        
        const uploadResult = await uploadArticleImage(
          req.files.imageEnglish[0], 
          id, 
          'preview_en', 
          '', 
          '', 
          imageCaptionEnglish || '', 
          ''
        );
        imageEnglishUrl = await getSignedUrlForImage(uploadResult.s3_key);
      } catch (previewImageError) {
        logger.error('Error uploading English preview image:', previewImageError);
      }
    }

    if (req.files?.imageSpanish) {
      try {
        // Delete existing Spanish preview image if any
        await mysqlConnection.promise().query(
          'DELETE FROM article_images WHERE article_id = ? AND image_type = "preview_es"',
          [id]
        );
        
        const uploadResult = await uploadArticleImage(
          req.files.imageSpanish[0], 
          id, 
          'preview_es', 
          '', 
          '', 
          '', 
          imageCaptionSpanish || ''
        );
        imageSpanishUrl = await getSignedUrlForImage(uploadResult.s3_key);
      } catch (previewImageError) {
        logger.error('Error uploading Spanish preview image:', previewImageError);
      }
    }

    // If no new images uploaded, get existing URLs
    if (!imageEnglishUrl || !imageSpanishUrl) {
      const [existingImages] = await mysqlConnection.promise().query(
        `SELECT 
          image_type,
          s3_key,
          caption_en,
          caption_es
        FROM article_images 
        WHERE article_id = ? AND image_type IN ('preview_en', 'preview_es')`,
        [id]
      );

      for (const img of existingImages) {
        if (img.image_type === 'preview_en' && !imageEnglishUrl) {
          imageEnglishUrl = await getSignedUrlForImage(img.s3_key);
        } else if (img.image_type === 'preview_es' && !imageSpanishUrl) {
          imageSpanishUrl = await getSignedUrlForImage(img.s3_key);
        }
      }
    }

    // Replace S3 key placeholders with signed URLs in content for response
    const contentEnglishWithUrls = await replaceS3KeysWithSignedUrls(processedContentEnglish);
    const contentSpanishWithUrls = await replaceS3KeysWithSignedUrls(processedContentSpanish);

    const response = {
      id: parseInt(id),
      titleEnglish,
      titleSpanish,
      subtitleEnglish: subtitleEnglish || null,
      subtitleSpanish: subtitleSpanish || null,
      contentEnglish: contentEnglishWithUrls,
      contentSpanish: contentSpanishWithUrls,
      author,
      author_gender,
      date: publicationDate,
      categoryId: parseInt(categoryId),
      priority: managedPriority,
      article_status_id: parseInt(article_status_id) || 1,
      imageEnglishUrl,
      imageSpanishUrl,
      imageCaptionEnglish: imageCaptionEnglish || null,
      imageCaptionSpanish: imageCaptionSpanish || null,
      updatedAt: new Date().toISOString()
    };

    res.json(response);

  } catch (error) {
    console.error('Error updating article:', error);
    logger.error('Error updating article:', error);
    res.status(500).json('Internal server error');
  }
});

// Delete article
router.delete('/article/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  
  if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
    return res.status(401).json('Unauthorized');
  }

  try {
    const { id } = req.params;

    // Check if article exists
    const [existingArticle] = await mysqlConnection.promise().query(
      'SELECT id FROM article WHERE id = ?',
      [id]
    );

    if (existingArticle.length === 0) {
      return res.status(404).json('Article not found');
    }

    // Get all associated images to delete from S3 (including content images)
    const [images] = await mysqlConnection.promise().query(
      'SELECT s3_key, image_type FROM article_images WHERE article_id = ?',
      [id]
    );

    // Delete images from S3
    if (images.length > 0) {
      try {
        const deleteParams = {
          Bucket: bucketName,
          Delete: {
            Objects: images.map(img => ({ Key: img.s3_key })),
            Quiet: false,
          },
        };

        const deleteCommand = new DeleteObjectsCommand(deleteParams);
        await s3.send(deleteCommand);
        logger.info(`Deleted ${images.length} images from S3 for article ${id}`);
      } catch (s3Error) {
        logger.error('Error deleting images from S3:', s3Error);
        // Continue with article deletion even if S3 cleanup fails
      }
    }

    // Delete article (CASCADE will delete associated images from DB)
    await mysqlConnection.promise().query(
      'DELETE FROM article WHERE id = ?',
      [id]
    );

    res.json({ 
      message: 'Article deleted successfully',
      deletedImages: images.length 
    });

  } catch (error) {
    console.error('Error deleting article:', error);
    logger.error('Error deleting article:', error);
    res.status(500).json('Internal server error');
  }
});

// Upload content image for rich text editor
router.post('/article/upload-image', verifyToken, articleUpload, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  
  if (cabecera.role !== 'admin' && cabecera.role !== 'content_manager') {
    return res.status(401).json('Unauthorized');
  }

  try {
    if (!req.files?.image) {
      return res.status(400).json('No image file provided');
    }

    const file = req.files.image[0];
    const fileName = randomImageName();

    // Upload to S3
    const uploadParams = {
      Bucket: bucketName,
      Key: fileName,
      Body: file.buffer,
      ContentType: file.mimetype,
    };

    const command = new PutObjectCommand(uploadParams);
    await s3.send(command);

    // Generate signed URL for immediate use
    const imageUrl = await getSignedUrlForImage(fileName);

    res.json({ imageUrl });

  } catch (error) {
    console.error('Error uploading content image:', error);
    logger.error('Error uploading content image:', error);
    res.status(500).json('Internal server error');
  }
});

module.exports = router;
