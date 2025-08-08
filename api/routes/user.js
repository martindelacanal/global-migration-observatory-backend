const express = require('express');
const router = express.Router();
const mysqlConnection = require('../connection/connection');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const axios = require('axios');
const logger = require('../utils/logger.js');
const createCsvStringifier = require('csv-writer').createObjectCsvStringifier;
const JSZip = require('jszip');
const multer = require('multer');
const moment = require('moment');
const storage = multer.memoryStorage();

// S3 INICIO
const S3Client = require("@aws-sdk/client-s3").S3Client;
const PutObjectCommand = require("@aws-sdk/client-s3").PutObjectCommand;
const GetObjectCommand = require("@aws-sdk/client-s3").GetObjectCommand;
const { DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { DeleteObjectsCommand } = require("@aws-sdk/client-s3");
const getSignedUrl = require("@aws-sdk/s3-request-presigner").getSignedUrl;

const bucketName = process.env.BUCKET_NAME;
const bucketRegion = process.env.BUCKET_REGION;
const accessKey = process.env.ACCESS_KEY;
const secretAccessKey = process.env.SECRET_ACCESS_KEY;

const crypto = require("crypto");
const randomImageName = (bytes = 32) =>
  crypto.randomBytes(bytes).toString("hex");

const s3 = new S3Client({
  credentials: {
    accessKeyId: accessKey,
    secretAccessKey: secretAccessKey,
  },
  region: bucketRegion,
});
// S3 FIN

router.get('/ping', (req, res) => {
  res.status(200).send();
});

const jwtSignAsync = (data, secret, options) => {
  return new Promise((resolve, reject) => {
    jwt.sign(data, secret, options, (err, token) => {
      if (err) {
        reject(err);
      } else {
        resolve(token);
      }
    });
  });
};

router.post('/signin', (req, res) => {
  const email = req.body.email || null;
  const password = req.body.password || null;
  const remember = req.body.remember || null;
  console.log(req.body);

  mysqlConnection.query('SELECT user.id, \
                                  user.firstname, \
                                  user.lastname, \
                                  user.username, \
                                  user.email, \
                                  user.password, \
                                  user.reset_password as reset_password, \
                                  role.name AS role, \
                                  user.enabled as enabled\
                                  FROM user \
                                  INNER JOIN role ON role.id = user.role_id \
                                  WHERE (user.email = ? or user.username = ?) \
                                  AND user.enabled = "Y" \
                                  LIMIT 1',
    [email, email],
    async (err, rows, fields) => {
      if (!err) {
        console.log(rows);
        if (rows.length > 0) {
          const user = rows[0];

          // Verificar password
          const isPasswordValid = await bcryptjs.compare(password, user.password);

          if (isPasswordValid && user.enabled === 'Y') {
            const reset_password = user.reset_password;

            // Limpiar datos sensibles antes de crear el token
            delete user.reset_password;
            delete user.password;

            let data = JSON.stringify(user);
            console.log("los datos del token son: " + data);

            try {
              // Determinar duración del token basado en remember
              const tokenExpiration = remember === true ? '7d' : '1h';

              const token = await jwtSignAsync({ data }, process.env.JWT_SECRET, { expiresIn: tokenExpiration });

              logger.info(`user id: ${user.id} logueado - remember: ${remember} - token expires in: ${tokenExpiration}`);
              res.status(200).json({
                token: token,
                reset_password: reset_password
              });

            } catch (tokenErr) {
              logger.error(tokenErr);
              return res.status(500).send();
            }
          } else {
            logger.info(`user ${email} credenciales incorrectas`);
            res.status(401).send();
          }
        } else {
          logger.info(`user ${email} no encontrado`);
          res.status(401).send();
        }
      } else {
        logger.error(err);
        console.log(err);
        res.status(500).send();
      }
    }
  );
});

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

router.get('/refresh-token', verifyToken, (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'stocker' || cabecera.role === 'delivery' || cabecera.role === 'beneficiary' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    jwt.sign({ data: req.data.data }, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      res.status(200).json({ token: token });
    });
  } else {
    res.status(401).json('Unauthorized');
  }
});


router.post('/signup', async (req, res) => {
  // const cabecera = JSON.parse(req.data.data);
  console.log(req.body);

  firstForm = req.body.firstForm;
  secondForm = req.body.secondForm;

  const role_id = 5;
  const username = firstForm.username || null;
  let passwordHash = await bcryptjs.hash(firstForm.password, 8);
  const firstname = firstForm.firstName || null;
  const lastname = firstForm.lastName || null;
  const dateOfBirth = firstForm.dateOfBirth || null;
  const email = firstForm.email || null;
  const phone = firstForm.phone.toString() || null;
  const zipcode = firstForm.zipcode.toString() || null;
  const location_id = firstForm.destination || null;
  const householdSize = firstForm.householdSize || null;
  const gender = firstForm.gender || null;
  const ethnicity = firstForm.ethnicity || null;
  const otherEthnicity = firstForm.otherEthnicity || null;

  try {

    const [rows_client_id] = await mysqlConnection.promise().query('SELECT client_id FROM client_location WHERE location_id = ?', [location_id]);
    let client_id = null;
    if (rows_client_id.length > 0) {
      client_id = rows_client_id[0].client_id;
    }

    const [rows] = await mysqlConnection.promise().query('insert into user(username, \
                                                          password, \
                                                          email, \
                                                          role_id, \
                                                          client_id, \
                                                          firstname, \
                                                          lastname, \
                                                          date_of_birth, \
                                                          phone, \
                                                          zipcode, \
                                                          first_location_id, \
                                                          location_id, \
                                                          household_size, \
                                                          gender_id, \
                                                          ethnicity_id, \
                                                          other_ethnicity) \
                                                          values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [username, passwordHash, email, role_id, client_id, firstname, lastname, dateOfBirth, phone, zipcode, location_id, location_id, householdSize, gender, ethnicity, otherEthnicity]);
    if (rows.affectedRows > 0) {
      // save inserted user id
      const user_id = rows.insertId;
      // insertar en tabla client_user el client_id y el user_id si client_id no es null
      if (client_id) {
        const [rows_client_user] = await mysqlConnection.promise().query('insert into client_user(client_id, user_id) values(?,?)', [client_id, user_id]);
      }
      // insert user_question, iterate array of questions and insert each question with its answer
      for (let i = 0; i < secondForm.length; i++) {
        const question_id = secondForm[i].question_id;
        const answer_type_id = secondForm[i].answer_type_id;
        const answer = secondForm[i].answer;
        var user_question_id = null;
        if (answer) {
          switch (answer_type_id) {
            case 1: // texto
              const [rows] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id, answer_text) values(?,?,?,?)',
                [user_id, question_id, answer_type_id, answer]);
              break;
            case 2: // numero
              const [rows2] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id, answer_number) values(?,?,?,?)',
                [user_id, question_id, answer_type_id, answer]);
              break;
            case 3: // opcion simple
              const [rows3] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id) values(?,?,?)',
                [user_id, question_id, answer_type_id]);
              user_question_id = rows3.insertId;
              const [rows4] = await mysqlConnection.promise().query('insert into user_question_answer(user_question_id, answer_id) values(?,?)',
                [user_question_id, answer]);
              break;
            case 4: // opcion multiple
              if (answer.length > 0) {
                const [rows5] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id) values(?,?,?)',
                  [user_id, question_id, answer_type_id]);
                user_question_id = rows5.insertId;
                for (let j = 0; j < answer.length; j++) {
                  const answer_id = answer[j];
                  const [rows6] = await mysqlConnection.promise().query('insert into user_question_answer(user_question_id, answer_id) values(?,?)',
                    [user_question_id, answer_id]);
                }
              }
              break;
            default:
              break;
          }
        }
      }

      res.status(200).json('Data inserted successfully');

      // After successful user creation, add to Mailchimp
      try {
        // get gender name and ethnicity name from their ids
        const [rowsGender] = await mysqlConnection.promise().query('SELECT name FROM gender WHERE id = ?', gender);
        const [rowsEthnicity] = await mysqlConnection.promise().query('SELECT name FROM ethnicity WHERE id = ?', ethnicity);

        const gender_name = rowsGender && rowsGender[0]?.name || '';
        const ethnicity_name = rowsEthnicity && rowsEthnicity[0]?.name || '';

        await addSubscriberToMailchimp({
          email: email,
          firstname: firstname,
          lastname: lastname,
          phone: phone,
          zipcode: zipcode,
          dateOfBirth: dateOfBirth,
          gender: gender_name,
          ethnicity: ethnicity_name,
          otherEthnicity: otherEthnicity
        });

      } catch (mailchimpError) {
        // Update user to set mailchimp_error to 'Y'
        await mysqlConnection.promise().query('UPDATE user SET mailchimp_error = "Y" WHERE id = ?', [user_id]);

      }
      await mysqlConnection.promise().query('UPDATE user SET mailchimp_error = "Y" WHERE id = ?', [user_id]);
    } else {
      res.status(500).json('Could not create user');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.put('/admin/reset-password', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const { id, password } = req.body;
    if (id && password) {
      let passwordHash = await bcryptjs.hash(password, 8);
      try {
        const [rows] = await mysqlConnection.promise().query(
          `update client set password = '${passwordHash}' where id = '${id}'`
        );
        if (rows.affectedRows > 0) {
          res.json('Contraseña actualizada correctamente');
        } else {
          res.status(500).json('No se pudo actualizar la contraseña');
        }
      } catch (err) {
        throw err;
      }
    } else {
      res.status(400).json('No se ingreso ningun parametro');
    }
  } else {
    res.status(401).send();
  }
});

// ================= ARTICLE ENDPOINTS =================

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

// Helper function to generate signed URL for S3 object
async function getSignedUrlForImage(s3Key, expiresIn = 3600) {
  try {
    const command = new GetObjectCommand({
      Bucket: bucketName,
      Key: s3Key,
    });
    
    return await getSignedUrl(s3, command, { expiresIn });
  } catch (error) {
    logger.error(`Error generating signed URL for ${s3Key}:`, error);
    return null;
  }
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
          const fileName = randomImageName();
          
          const uploadParams = {
            Bucket: bucketName,
            Key: fileName,
            Body: imageBuffer,
            ContentType: imageData.mimeType,
          };

          const command = new PutObjectCommand(uploadParams);
          await s3.send(command);

          // Save image metadata to database
          const altTextEn = language === 'en' ? imageData.altText : '';
          const altTextEs = language === 'es' ? imageData.altText : '';

          await mysqlConnection.promise().query(
            `INSERT INTO article_images (
              article_id, image_type, s3_key, s3_bucket, file_hash,
              mime_type, file_size, alt_text_en, alt_text_es, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              articleId, 'content', fileName, bucketName, fileHash,
              imageData.mimeType, imageBuffer.length, altTextEn, altTextEs, displayOrder
            ]
          );

          s3Key = fileName;
          displayOrder++;
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

      logger.info(`Cleaned up ${imagesToDelete.length} orphaned content images for article ${articleId}`);
    }

  } catch (error) {
    logger.error('Error cleaning up orphaned images:', error);
    // Don't throw error as this is cleanup operation
  }
}

// Helper function to replace S3 key placeholders with signed URLs in content
async function replaceS3KeysWithSignedUrls(content) {
  try {
    // Find all S3 key placeholders in the format {{S3_KEY:filename}}
    const s3KeyRegex = /\{\{S3_KEY:([^}]+)\}\}/g;
    let modifiedContent = content;
    let match;

    while ((match = s3KeyRegex.exec(content)) !== null) {
      const s3Key = match[1];
      const placeholder = match[0];
      
      try {
        const signedUrl = await getSignedUrlForImage(s3Key);
        if (signedUrl) {
          modifiedContent = modifiedContent.replace(placeholder, signedUrl);
        } else {
          // If we can't generate signed URL, remove the image tag
          logger.warn(`Could not generate signed URL for ${s3Key}, removing image`);
          modifiedContent = modifiedContent.replace(
            new RegExp(`<img[^>]*src="${placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"[^>]*>`, 'g'),
            ''
          );
        }
      } catch (urlError) {
        logger.error(`Error generating signed URL for ${s3Key}:`, urlError);
        // Continue with other images
      }
    }

    return modifiedContent;
  } catch (error) {
    logger.error('Error replacing S3 keys with signed URLs:', error);
    return content; // Return original content if processing fails
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
  
  if (cabecera.role !== 'admin') {
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
        priority || null, article_status_id || 1, slugEn, slugEs
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
        const imageResult = await uploadArticleImage(
          req.files.imageEnglish[0], 
          articleId, 
          'preview_en',
          imageCaptionEnglish || '',
          '',
          imageCaptionEnglish || '',
          ''
        );
        imageEnglishUrl = await getSignedUrlForImage(imageResult.s3_key);
      } catch (previewImageError) {
        logger.error('Error uploading English preview image:', previewImageError);
      }
    }

    if (req.files?.imageSpanish) {
      try {
        const imageResult = await uploadArticleImage(
          req.files.imageSpanish[0], 
          articleId, 
          'preview_es',
          '',
          imageCaptionSpanish || '',
          '',
          imageCaptionSpanish || ''
        );
        imageSpanishUrl = await getSignedUrlForImage(imageResult.s3_key);
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
      priority: priority ? parseInt(priority) : null,
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

// Get articles with pagination
router.get('/article', async (req, res) => {
  try {
    const { page = 1, limit = 10, lang = 'en' } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Get total count
    const [countResult] = await mysqlConnection.promise().query(
      'SELECT COUNT(*) as total FROM article'
    );
    const total = countResult[0].total;

    // Get articles with preview images - always fetch both languages
    const query = `
      SELECT 
        a.id,
        a.title_en as titleEnglish,
        a.title_es as titleSpanish,
        a.subtitle_en as subtitleEnglish,
        a.subtitle_es as subtitleSpanish,
        a.content_en as contentEnglish,
        a.content_es as contentSpanish,
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

    // Format response with signed URLs
    const formattedArticles = await Promise.all(articles.map(async (article) => {
      // Generate signed URLs for preview images
      let imageEnglishUrl = null;
      let imageSpanishUrl = null;

      if (article.previewEnglishKey) {
        imageEnglishUrl = await getSignedUrlForImage(article.previewEnglishKey);
      }
      if (article.previewSpanishKey) {
        imageSpanishUrl = await getSignedUrlForImage(article.previewSpanishKey);
      }

      // Replace S3 key placeholders with signed URLs in content for both languages
      let contentEnglishWithUrls = article.contentEnglish;
      let contentSpanishWithUrls = article.contentSpanish;
      
      if (contentEnglishWithUrls) {
        contentEnglishWithUrls = await replaceS3KeysWithSignedUrls(contentEnglishWithUrls);
      }
      if (contentSpanishWithUrls) {
        contentSpanishWithUrls = await replaceS3KeysWithSignedUrls(contentSpanishWithUrls);
      }

      return {
        id: article.id,
        titleEnglish: article.titleEnglish,
        titleSpanish: article.titleSpanish,
        subtitleEnglish: article.subtitleEnglish,
        subtitleSpanish: article.subtitleSpanish,
        contentEnglish: contentEnglishWithUrls,
        contentSpanish: contentSpanishWithUrls,
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
        imageEnglishUrl,
        imageSpanishUrl,
        imageCaptionEnglish: article.imageCaptionEnglish,
        imageCaptionSpanish: article.imageCaptionSpanish,
        createdAt: article.createdAt,
        updatedAt: article.updatedAt
      };
    }));

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

// Get article by ID
router.get('/article/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { lang = 'en' } = req.query;

    // Get article with images
    const [articles] = await mysqlConnection.promise().query(
      `SELECT 
        a.*,
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
      date: article.publication_date,
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

// Update article
router.put('/article/:id', verifyToken, articleUpload, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  
  if (cabecera.role !== 'admin') {
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

    // Process content images (convert base64 to S3 URLs)
    let processedContentEnglish = contentEnglish;
    let processedContentSpanish = contentSpanish;

    try {
      processedContentEnglish = await processContentImages(contentEnglish, id, 'en');
      processedContentSpanish = await processContentImages(contentSpanish, id, 'es');

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
        priority || null, article_status_id || 1, slugEn, slugEs, id
      ]
    );

    let imageEnglishUrl = null;
    let imageSpanishUrl = null;

    // Handle new preview images
    if (req.files?.imageEnglish) {
      try {
        // Get existing English preview image to delete from S3
        const [existingEnImage] = await mysqlConnection.promise().query(
          'SELECT s3_key FROM article_images WHERE article_id = ? AND image_type = "preview_en"',
          [id]
        );

        // Delete existing English preview image from S3
        if (existingEnImage.length > 0) {
          const deleteParams = {
            Bucket: bucketName,
            Key: existingEnImage[0].s3_key
          };
          const deleteCommand = new DeleteObjectCommand(deleteParams);
          await s3.send(deleteCommand);
        }

        // Delete from database
        await mysqlConnection.promise().query(
          `DELETE FROM article_images WHERE article_id = ? AND image_type = 'preview_en'`,
          [id]
        );
        
        // Upload new English preview
        const imageResult = await uploadArticleImage(
          req.files.imageEnglish[0], 
          id, 
          'preview_en',
          imageCaptionEnglish || '',
          '',
          imageCaptionEnglish || '',
          ''
        );
        imageEnglishUrl = await getSignedUrlForImage(imageResult.s3_key);
      } catch (previewImageError) {
        logger.error('Error updating English preview image:', previewImageError);
      }
    }

    if (req.files?.imageSpanish) {
      try {
        // Get existing Spanish preview image to delete from S3
        const [existingEsImage] = await mysqlConnection.promise().query(
          'SELECT s3_key FROM article_images WHERE article_id = ? AND image_type = "preview_es"',
          [id]
        );

        // Delete existing Spanish preview image from S3
        if (existingEsImage.length > 0) {
          const deleteParams = {
            Bucket: bucketName,
            Key: existingEsImage[0].s3_key
          };
          const deleteCommand = new DeleteObjectCommand(deleteParams);
          await s3.send(deleteCommand);
        }

        // Delete from database
        await mysqlConnection.promise().query(
          `DELETE FROM article_images WHERE article_id = ? AND image_type = 'preview_es'`,
          [id]
        );
        
        // Upload new Spanish preview
        const imageResult = await uploadArticleImage(
          req.files.imageSpanish[0], 
          id, 
          'preview_es',
          '',
          imageCaptionSpanish || '',
          '',
          imageCaptionSpanish || ''
        );
        imageSpanishUrl = await getSignedUrlForImage(imageResult.s3_key);
      } catch (previewImageError) {
        logger.error('Error updating Spanish preview image:', previewImageError);
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
      priority: priority ? parseInt(priority) : null,
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
  
  if (cabecera.role !== 'admin') {
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
        // Continue with database deletion even if S3 deletion fails
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
  
  if (cabecera.role !== 'admin') {
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

// Process existing article content images (migration utility)
router.post('/article/:id/process-content-images', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  
  if (cabecera.role !== 'admin') {
    return res.status(401).json('Unauthorized');
  }

  try {
    const { id } = req.params;

    // Check if article exists and get current content
    const [articles] = await mysqlConnection.promise().query(
      'SELECT content_en, content_es FROM article WHERE id = ?',
      [id]
    );

    if (articles.length === 0) {
      return res.status(404).json('Article not found');
    }

    const article = articles[0];
    let processedContentEnglish = article.content_en;
    let processedContentSpanish = article.content_es;
    let imagesProcessed = 0;

    // Process English content
    const englishImages = extractBase64Images(article.content_en);
    if (englishImages.length > 0) {
      processedContentEnglish = await processContentImages(article.content_en, id, 'en');
      imagesProcessed += englishImages.length;
    }

    // Process Spanish content
    const spanishImages = extractBase64Images(article.content_es);
    if (spanishImages.length > 0) {
      processedContentSpanish = await processContentImages(article.content_es, id, 'es');
      imagesProcessed += spanishImages.length;
    }

    // Update article with processed content if changes were made
    if (processedContentEnglish !== article.content_en || processedContentSpanish !== article.content_es) {
      await mysqlConnection.promise().query(
        'UPDATE article SET content_en = ?, content_es = ?, modification_date = CURRENT_TIMESTAMP WHERE id = ?',
        [processedContentEnglish, processedContentSpanish, id]
      );

      res.json({
        message: 'Content images processed successfully',
        imagesProcessed: imagesProcessed,
        contentUpdated: true
      });
    } else {
      res.json({
        message: 'No base64 images found in content',
        imagesProcessed: 0,
        contentUpdated: false
      });
    }

  } catch (error) {
    console.error('Error processing content images:', error);
    logger.error('Error processing content images:', error);
    res.status(500).json('Internal server error');
  }
});

// Batch process all articles with base64 images (migration utility)
router.post('/article/batch-process-content-images', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  
  if (cabecera.role !== 'admin') {
    return res.status(401).json('Unauthorized');
  }

  try {
    // Get all articles that might have base64 images
    const [articles] = await mysqlConnection.promise().query(
      `SELECT id, content_en, content_es 
       FROM article 
       WHERE content_en LIKE '%data:image%' OR content_es LIKE '%data:image%'`
    );

    if (articles.length === 0) {
      return res.json({
        message: 'No articles found with base64 images',
        articlesProcessed: 0,
        totalImagesProcessed: 0
      });
    }

    let articlesProcessed = 0;
    let totalImagesProcessed = 0;
    const processedArticles = [];

    for (const article of articles) {
      try {
        let processedContentEnglish = article.content_en;
        let processedContentSpanish = article.content_es;
        let articleImagesProcessed = 0;

        // Process English content
        const englishImages = extractBase64Images(article.content_en);
        if (englishImages.length > 0) {
          processedContentEnglish = await processContentImages(article.content_en, article.id, 'en');
          articleImagesProcessed += englishImages.length;
        }

        // Process Spanish content
        const spanishImages = extractBase64Images(article.content_es);
        if (spanishImages.length > 0) {
          processedContentSpanish = await processContentImages(article.content_es, article.id, 'es');
          articleImagesProcessed += spanishImages.length;
        }

        // Update article if changes were made
        if (processedContentEnglish !== article.content_en || processedContentSpanish !== article.content_es) {
          await mysqlConnection.promise().query(
            'UPDATE article SET content_en = ?, content_es = ?, modification_date = CURRENT_TIMESTAMP WHERE id = ?',
            [processedContentEnglish, processedContentSpanish, article.id]
          );

          articlesProcessed++;
          totalImagesProcessed += articleImagesProcessed;
          processedArticles.push({
            id: article.id,
            imagesProcessed: articleImagesProcessed
          });
        }

        // Add small delay to prevent overwhelming the system
        await new Promise(resolve => setTimeout(resolve, 100));

      } catch (articleError) {
        logger.error(`Error processing article ${article.id}:`, articleError);
        continue; // Continue with next article
      }
    }

    res.json({
      message: 'Batch processing completed',
      articlesProcessed: articlesProcessed,
      totalImagesProcessed: totalImagesProcessed,
      processedArticles: processedArticles
    });

  } catch (error) {
    console.error('Error batch processing content images:', error);
    logger.error('Error batch processing content images:', error);
    res.status(500).json('Internal server error');
  }
});

// ================= END ARTICLE ENDPOINTS =================

function verifyToken(req, res, next) {

  if (!req.headers.authorization) return res.status(401).json('No autorizado');

  const token = req.headers.authorization.substr(7);
  if (token !== '') {
    jwt.verify(token, process.env.JWT_SECRET, (error, authData) => {
      if (error) {
        res.status(403).json('Error en el token');
      } else {
        req.data = authData;
        next();
      }
    });
  } else {
    res.status(401).json('Token vacio');
  }

}

module.exports = router;