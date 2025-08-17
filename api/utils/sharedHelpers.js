const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const mysqlConnection = require('../connection/connection');
const logger = require('./logger.js');

// S3 IMPORTS
const S3Client = require("@aws-sdk/client-s3").S3Client;
const PutObjectCommand = require("@aws-sdk/client-s3").PutObjectCommand;
const GetObjectCommand = require("@aws-sdk/client-s3").GetObjectCommand;
const { DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { DeleteObjectsCommand } = require("@aws-sdk/client-s3");
const getSignedUrl = require("@aws-sdk/s3-request-presigner").getSignedUrl;
const crypto = require("crypto");

// In-memory cache for signed URLs
const signedUrlCache = new Map();
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes in milliseconds

// S3 Configuration
const bucketName = process.env.BUCKET_NAME;
const bucketRegion = process.env.BUCKET_REGION;
const accessKey = process.env.ACCESS_KEY;
const secretAccessKey = process.env.SECRET_ACCESS_KEY;

const randomImageName = (bytes = 32) =>
  crypto.randomBytes(bytes).toString("hex");

const s3 = new S3Client({
  credentials: {
    accessKeyId: accessKey,
    secretAccessKey: secretAccessKey,
  },
  region: bucketRegion,
});

// JWT helper function
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

// Token verification middleware
function verifyToken(req, res, next) {
  if (!req.headers.authorization) return res.status(401).json('No autorizado');

  const token = req.headers.authorization.substr(7);
  if (token !== '') {
    jwt.verify(token, process.env.JWT_SECRET, (error, authData) => {
      if (error) {
        res.status(401).json('Token invalido');
      } else {
        req.data = authData;
        next();
      }
    });
  } else {
    res.status(401).json('Token vacio');
  }
}

// Helper function to generate signed URL for S3 object with caching
async function getSignedUrlForImage(s3Key, expiresIn = 3600) {
  try {
    const cacheKey = `${s3Key}_${expiresIn}`;
    const now = Date.now();
    
    // Check cache first
    const cached = signedUrlCache.get(cacheKey);
    if (cached && (now - cached.timestamp) < CACHE_DURATION) {
      return cached.url;
    }
    
    const command = new GetObjectCommand({
      Bucket: bucketName,
      Key: s3Key,
    });
    
    const signedUrl = await getSignedUrl(s3, command, { expiresIn });
    
    // Cache the result
    signedUrlCache.set(cacheKey, {
      url: signedUrl,
      timestamp: now
    });
    
    // Clean old cache entries periodically
    if (signedUrlCache.size > 1000) {
      cleanExpiredCache();
    }
    
    return signedUrl;
  } catch (error) {
    logger.error(`Error generating signed URL for ${s3Key}:`, error);
    return null;
  }
}

// Helper function to clean expired cache entries
function cleanExpiredCache() {
  const now = Date.now();
  for (const [key, value] of signedUrlCache.entries()) {
    if ((now - value.timestamp) >= CACHE_DURATION) {
      signedUrlCache.delete(key);
    }
  }
}

// Helper function to generate multiple signed URLs in parallel
async function getSignedUrlsForImages(s3Keys, expiresIn = 3600) {
  if (!s3Keys || s3Keys.length === 0) return [];
  
  const promises = s3Keys.map(s3Key => getSignedUrlForImage(s3Key, expiresIn));
  return Promise.all(promises);
}

module.exports = {
  jwtSignAsync,
  verifyToken,
  getSignedUrlForImage,
  getSignedUrlsForImages,
  getSignedUrl,
  s3,
  bucketName,
  randomImageName,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  crypto,
  mysqlConnection,
  logger,
  bcryptjs
};
