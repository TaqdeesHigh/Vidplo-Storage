// Did my best to explain the code as much as possible!
const express = require('express');
const multer = require('multer');
const path = require('path');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegPath = require('@ffmpeg-installer/ffmpeg').path;
ffmpeg.setFfmpegPath(ffmpegPath);
const fs = require('fs');
const cors = require('cors');
const mysql = require('mysql2/promise');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000; // Port can be configured via environment variable or defaults to 3000
const videosDir = process.env.VIDEOS_DIR || path.join(__dirname, 'uploads', 'videos'); // Videos directory can be configured via environment variable or defaults to ./uploads/videos

// API Key for authentication - should be set in environment variables
const API_KEY = process.env.API_KEY;

if (!API_KEY) {
  console.error('API_KEY is not set in environment variables. Please set API_KEY to secure your API.');
  process.exit(1); // Exit if API key is not set, crucial for security
}

// Configure CORS based on environment variables, allows multiple origins
const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS ? process.env.CORS_ALLOWED_ORIGINS.split(',') : ['http://localhost:3000']; // Default to localhost if not set
app.use(cors({
  origin: allowedOrigins, // Use dynamically configured origins
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Middleware to authenticate API requests using API Key.
 * API Key should be passed in the Authorization header as Bearer token.
 */
const authenticateApiKey = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const apiKey = authHeader && authHeader.split(' ')[1];

  if (apiKey && apiKey === API_KEY) {
    next(); // API key is valid, proceed to the next middleware/route handler
  } else {
    console.log('API Key is invalid');
    res.status(401).json({ error: 'Invalid or missing API key' }); // Return 401 for unauthorized access
  }
};

// Database configuration, loaded from environment variables
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
};

let pool; // Database connection pool

/**
 * Initializes the database connection pool.
 * Exits the process if database connection fails.
 */
async function initializeDatabase() {
  try {
    pool = await mysql.createPool(dbConfig);
    console.log('Database connection established');
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1); // Exit if database connection fails, critical for the app to function
  }
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userEmail = req.body.userEmail || req.query.userEmail;
    if (!userEmail) {
      return cb(new Error('User email is required')); // Reject upload if user email is missing
    }
    const dir = path.join(videosDir, userEmail); // Store videos in user-specific directory within videosDir
    fs.mkdirSync(dir, { recursive: true }); // Ensure directory exists, create if not
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const filename = req.body.filename || file.originalname; // Use provided filename or original filename
    cb(null, filename);
  }
});

const upload = multer({ storage: storage });

/**
 * Checks if the current viewer has access to the video based on privacy settings and user session.
 * @param {string} token - Video token.
 * @param {string} ipAddress - Viewer's IP address.
 * @returns {Promise<boolean>} - True if access is allowed, false otherwise.
 */
async function checkVideoAccess(token, ipAddress) {
  try {
    // First check if video is public or private and get user_email from file_tokens
    const [videoData] = await pool.execute(
      `SELECT fm.privacy, ft.user_email
       FROM file_meta fm
       JOIN file_tokens ft ON fm.token = ft.token
       WHERE fm.token = ?`,
      [token]
    );

    if (videoData.length === 0) {
      throw new Error('Video not found'); // Video not found for the given token
    }

    const { privacy, user_email } = videoData[0];

    // If video is public, allow access
    if (privacy === 'public') {
      return true;
    }

    // For private videos, check if viewer is the owner by session IP address
    const [sessionRows] = await pool.execute(
      `SELECT ws.* FROM website_sessions ws
       INNER JOIN users u ON ws.user_id = u.id
       WHERE ws.ip_address = ?
       AND ws.last_activity = (
         SELECT MAX(last_activity)
         FROM website_sessions
         WHERE ip_address = ?
       )`,
      [ipAddress, ipAddress]
    );

    if (sessionRows.length === 0) {
      return false; // No active session found for this IP
    }

    // Check if session user is the video owner
    const [userRows] = await pool.execute(
      'SELECT email FROM users WHERE id = ?',
      [sessionRows[0].user_id]
    );

    return userRows[0]?.email === user_email; // Access allowed if session user's email matches video owner's email

  } catch (error) {
    console.error('Error checking video access:', error);
    throw error; // Propagate error for handling in route
  }
}

/**
 * Increments the view count for a video, ensuring each IP address is counted only once.
 * @param {string} token - Video token.
 * @param {string} ipAddress - Viewer's IP address.
 * @returns {Promise<boolean>} - True if view count was incremented, false otherwise.
 */
async function incrementViewCount(token, ipAddress) {
  try {
      // Get current views_ip and count
      const [currentData] = await pool.execute(
          'SELECT views, views_ip FROM file_meta WHERE token = ?',
          [token]
      );

      if (currentData.length === 0) {
          console.error('Token not found in file_meta:', token);
          return false; // Token not found, cannot increment view count
      }

      let viewsIpArray = [];
      try {
          // Parse existing IPs or initialize empty array if null
          viewsIpArray = currentData[0].views_ip ? JSON.parse(currentData[0].views_ip) : [];
      } catch (error) {
          console.error('Error parsing views_ip:', error);
          viewsIpArray = []; // Initialize to empty array in case of parsing error
      }

      // Check if this IP has already viewed
      if (!viewsIpArray.includes(ipAddress)) {
          // Add the new IP
          viewsIpArray.push(ipAddress);

          // Update the database with new IP array and increment view count
          await pool.execute(
              'UPDATE file_meta SET views = views + 1, views_ip = ? WHERE token = ?',
              [JSON.stringify(viewsIpArray), token]
          );

          return true; // View was counted
      }

      return false; // View was not counted (IP already exists)

  } catch (error) {
      console.error('Error in incrementViewCount:', error);
      throw error; // Propagate error for handling in route
  }
}

/**
 * Extracts client IP address from request headers.
 * Handles various headers for different proxy setups.
 * @param {express.Request} req - Express request object.
 * @returns {string|undefined} - Client IP address or undefined if not found.
 */
function getClientIp(req) {
  return req.headers['cf-connecting-ip'] || // Cloudflare
         req.headers['x-forwarded-for']?.split(',')[0] || // Standard proxy header
         req.headers['x-real-ip'] || // Nginx proxy/LB
         req.connection.remoteAddress; // Fallback to connection remote address
}

// Endpoint to record video view
app.post('/api/record-view/:token', async (req, res) => {
  const { token } = req.params;
  const ipAddress = getClientIp(req); // Get client IP address

  if (!ipAddress) {
      return res.status(400).json({ error: 'Could not determine IP address' }); // Cannot record view without IP
  }

  try {
      const wasViewCounted = await incrementViewCount(token, ipAddress); // Increment view count in database

      res.json({
          success: true,
          viewCounted: wasViewCounted // Respond with success status and if view was counted
      });
  } catch (error) {
      console.error('Error recording view:', error);
      res.status(500).json({ error: 'Failed to record view' }); // Internal server error for view recording failure
  }
});

// Endpoint to receive video uploads
app.post('/receive', authenticateApiKey, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' }); // Reject if no file is uploaded
  }

  const userEmail = req.body.userEmail || req.query.userEmail;
  const fileName = req.file.filename;

  if (!userEmail) {
    return res.status(400).json({ error: 'User email is required' }); // Reject if user email is missing
  }

  try {
    const filePath = req.file.path;
    const fileSize = req.file.size;
    const token = uuidv4(); // Generate unique token for the uploaded video

    // Generate thumbnail for the video
    const thumbnailPath = path.join(path.dirname(filePath), `${path.basename(filePath, path.extname(filePath))}_thumbnail.jpg`);
    await generateThumbnail(filePath, thumbnailPath);

    const backendUrl = process.env.BACKEND_SERVER_URL; // URL for backend metadata service from environment variables
    if (!backendUrl) {
      throw new Error('BACKEND_SERVER_URL is not set in environment variables. Metadata creation might fail.');
    }

    // Create JSON metadata file for the video (using backend service)
    try {
      await axios.post(`${backendUrl}/create-metadata`, {
        fileName,
        userEmail,
        fileSize,
        token
      }, {
        headers: {
          'Authorization': `Bearer ${process.env.API_KEY}` // Pass API key for backend service authentication
        }
      });
    } catch (error) {
      console.error('Error creating metadata:', error);
      throw new Error('Failed to create metadata'); // Metadata creation failed
    }

    // Start video encoding process in different qualities based on user plan
    const userPlan = await getUserPlan(userEmail);
    const outputDir = path.dirname(filePath);
    encodeVideo(filePath, outputDir, path.basename(filePath, path.extname(filePath)), userPlan)
      .then(async (encodedQualities) => {
        // Update database with encoded qualities after successful encoding
        await pool.execute(
          'UPDATE file_tokens SET encoded_qualities = ? WHERE token = ?',
          [JSON.stringify(encodedQualities), token]
        );
      })
      .catch(error => {
        console.error('Error encoding video:', error);
      });

    res.json({
      message: 'File uploaded successfully. Encoding in progress.',
      token: token // Respond with success message and video token
    });
  } catch (error) {
    console.error('Error processing upload:', error);
    res.status(500).json({ error: 'Failed to process upload' }); // Internal server error for upload processing failure
  }
});

/**
 * Encodes a video into multiple qualities based on user plan.
 * @param {string} inputPath - Path to the input video file.
 * @param {string} outputDir - Directory to save encoded videos.
 * @param {string} fileName - Base filename for output videos.
 * @param {string} userPlan - User's plan (e.g., 'Free', 'Premium').
 * @returns {Promise<string[]>} - Array of encoded qualities.
 */
async function encodeVideo(inputPath, outputDir, fileName, userPlan) {
  // Define qualities based on user plan (Free or Premium)
  const qualities = userPlan === 'Premium' ? ['144p', '360p', '480p', '720p'] : ['144p', '360p', '480p'];
  const encodingPromises = qualities.map(quality => {
    return new Promise((resolve, reject) => {
      const outputPath = path.join(outputDir, `${fileName}_${quality}.mp4`);
      let command = ffmpeg(inputPath)
        .outputOptions('-c:a copy') // Copy audio codec
        .outputOptions('-preset fast'); // Use 'fast' preset for faster encoding

      // Set video size and bitrate based on quality
      switch (quality) {
        case '144p':
          command.size('256x144').outputOptions('-b:v 200k');
          break;
        case '360p':
          command.size('640x360').outputOptions('-b:v 800k');
          break;
        case '480p':
          command.size('854x480').outputOptions('-b:v 1000k');
          break;
        case '720p':
          command.size('1280x720').outputOptions('-b:v 2500k');
          break;
      }

      command.output(outputPath)
        .on('end', () => resolve(quality)) // Resolve promise with quality on successful encoding
        .on('error', (err) => reject(err)) // Reject promise with error on encoding failure
        .run(); // Execute ffmpeg command
    });
  });

  return Promise.all(encodingPromises); // Return a promise that resolves when all encodings are complete
}

// Endpoint to check video encoding status
app.get('/api/encoding-status/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const [rows] = await pool.execute('SELECT encoded_qualities FROM file_tokens WHERE token = ?', [token]); // Fetch encoded qualities from database

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' }); // Video not found for the given token
    }

    const encodedQualities = JSON.parse(rows[0].encoded_qualities || '[]'); // Parse encoded qualities or default to empty array
    const isEncodingComplete = encodedQualities.length > 0; // Encoding is considered complete if qualities array is not empty

    res.json({ isEncodingComplete, encodedQualities }); // Respond with encoding status and qualities
  } catch (error) {
    console.error('Error checking encoding status:', error);
    res.status(500).json({ error: 'Internal server error' }); // Internal server error for encoding status check failure
  }
});

/**
 * Generates a video thumbnail, ensuring it's not a black frame.
 * Tries multiple timestamps until a non-black frame is found or timeout reached.
 * @param {string} videoPath - Path to the video file.
 * @param {string} outputPath - Path to save the thumbnail.
 * @returns {Promise<void>}
 */
async function generateThumbnail(videoPath, outputPath) {
  return new Promise((resolve, reject) => {
    let thumbnailGenerated = false;
    let currentTime = 5; // Start at 5 seconds
    let videoWidth, videoHeight;

    // First, get the video dimensions using ffprobe
    ffmpeg.ffprobe(videoPath, (err, metadata) => {
      if (err) {
        reject(err); // Reject promise if ffprobe fails
        return;
      }

      const videoStream = metadata.streams.find(stream => stream.codec_type === 'video');
      if (!videoStream) {
        reject(new Error('No video stream found')); // Reject if no video stream is found
        return;
      }

      videoWidth = videoStream.width;
      videoHeight = videoStream.height;

      generateAndCheckThumbnail(); // Start recursive thumbnail generation and check
    });

    const generateAndCheckThumbnail = () => {
      const tempOutputPath = `${outputPath}_temp.jpg`; // Temporary path for thumbnail

      const aspectRatio = videoWidth / videoHeight;
      let thumbWidth, thumbHeight;
      if (aspectRatio > 1) {
        thumbWidth = 320;
        thumbHeight = Math.round(320 / aspectRatio);
      } else {
        thumbHeight = 320;
        thumbWidth = Math.round(320 * aspectRatio);
      }

      // Generate screenshot using ffmpeg
      ffmpeg(videoPath)
        .screenshots({
          timestamps: [`00:00:${currentTime.toString().padStart(2, '0')}`], // Timestamp for screenshot
          filename: path.basename(tempOutputPath),
          folder: path.dirname(tempOutputPath),
          size: `${thumbWidth}x${thumbHeight}` // Thumbnail size
        })
        .on('end', () => {
          // Check if the generated thumbnail has color information (not a black frame)
          ffmpeg.ffprobe(tempOutputPath, (err, metadata) => {
            if (err) {
              fs.unlinkSync(tempOutputPath); // Delete temp file on error
              reject(err);
              return;
            }

            const streams = metadata.streams;
            if (streams && streams.length > 0 && streams[0].codec_type === 'video') {
              const colorInfo = streams[0].color_range;

              if (colorInfo !== 'tv' && colorInfo !== 'pc') {
                fs.unlinkSync(tempOutputPath); // Delete temp thumbnail if it's a black frame
                currentTime += 5; // Increment timestamp to try next frame
                if (currentTime < 60) { // Try for up to 60 seconds
                  generateAndCheckThumbnail(); // Recursive call to try again with a different timestamp
                } else {
                  reject(new Error('Could not find a suitable thumbnail frame')); // Reject if no suitable frame found within timeout
                }
              } else {
                // Found a frame with color, use it as thumbnail
                fs.renameSync(tempOutputPath, outputPath); // Rename temp file to final thumbnail path
                thumbnailGenerated = true;
                resolve(); // Resolve promise as thumbnail is generated
              }
            } else {
              fs.unlinkSync(tempOutputPath); // Delete temp file if no valid video stream in metadata
              reject(new Error('Invalid video stream')); // Reject if invalid video stream
            }
          });
        })
        .on('error', (err) => {
          fs.unlinkSync(tempOutputPath); // Delete temp file on ffmpeg error
          reject(err); // Reject promise if ffmpeg command fails
        });
    };
  });
}

/**
 * Creates and stores a token for a video file in the database.
 * @param {string} filePath - Path to the video file.
 * @param {string} userEmail - User's email.
 * @param {number} fileSize - File size.
 * @returns {Promise<string>} - Generated token.
 */
async function createAndStoreToken(filePath, userEmail, fileSize) {
    const token = uuidv4(); // Generate unique token
    const insertQuery = 'INSERT INTO file_tokens (token, file_path, user_email, file_size) VALUES (?, ?, ?, ?)';
    await pool.execute(insertQuery, [token, filePath, userEmail, fileSize]); // Insert token and file info into database
    return token; // Return the generated token
}

// Endpoint to register a pre-existing token (potentially for internal use or integrations)
app.post('/register-token', authenticateApiKey, async (req, res) => {

  const { token, filePath, userEmail, fileSize } = req.body; // Expecting token, file path, user email and file size in request body

  try {
      const insertQuery = 'INSERT INTO file_tokens (token, file_path, user_email, file_size) VALUES (?, ?, ?, ?)';
      await pool.execute(insertQuery, [token, filePath, userEmail, fileSize]); // Insert provided token and file info into database
      res.json({ message: 'Token registered successfully' }); // Respond with success message
  } catch (error) {
      console.error('Error registering token:', error);
      res.status(500).json({ error: 'Failed to register token' }); // Internal server error for token registration failure
  }
});

// Endpoint to request a token for a file (if token doesn't already exist)
app.post('/request-token', authenticateApiKey, async (req, res) => {
  const { filePath, userEmail } = req.body; // Expecting file path and user email in request body

  if (!filePath || !userEmail) {
    return res.status(400).json({ error: 'File path and user email are required' }); // Reject if file path or user email is missing
  }

  const fullFilePath = path.join(videosDir, userEmail, filePath); // Construct full file path

  if (!fs.existsSync(fullFilePath)) {
    return res.status(404).json({ error: 'File not found' }); // Reject if file does not exist
  }

  try {
    // Check if a token already exists for this file
    const [existingTokens] = await pool.execute(
      'SELECT token FROM file_tokens WHERE file_path = ? AND user_email = ?',
      [fullFilePath, userEmail]
    );

    if (existingTokens.length > 0) {
      console.log('Existing token found for file:', fullFilePath);
      return res.json({ token: existingTokens[0].token }); // Return existing token if found
    }

    // If no token exists, create a new one
    const newToken = uuidv4(); // Generate new unique token
    const stats = fs.statSync(fullFilePath); // Get file stats to get file size

    await pool.execute(
      'INSERT INTO file_tokens (token, file_path, user_email, file_size) VALUES (?, ?, ?, ?)',
      [newToken, fullFilePath, userEmail, stats.size]
    ); // Insert new token and file info into database

    console.log('New token created for file:', fullFilePath);
    return res.json({ token: newToken }); // Return newly created token

  } catch (error) {
    console.error('Error processing token request:', error);
    res.status(500).json({ error: 'Failed to process token request', details: error.message }); // Internal server error for token request failure
  }
});

// Endpoint to list files for a given user
app.get('/files', authenticateApiKey, async (req, res) => {
  const userEmail = req.query.userEmail; // Get user email from query parameter

  if (!userEmail) {
    return res.status(400).json({ error: 'User email is required' }); // Reject if user email is missing
  }

  const userDir = path.join(videosDir, userEmail); // Construct user's video directory

  try {
    if (!fs.existsSync(userDir)) {
      return res.json([]); // Return empty array if user directory does not exist
    }

    const files = await fs.promises.readdir(userDir); // Read files in user directory
    const fileInfoPromises = files.map(async (fileName) => {
      const filePath = path.join(userDir, fileName);
      const stats = await fs.promises.stat(filePath); // Get file stats for each file
      return {
        name: fileName,
        size: stats.size,
        modifiedDate: stats.mtime // Include file name, size and modification date
      };
    });

    const fileInfos = await Promise.all(fileInfoPromises); // Wait for all file info promises to resolve
    res.json(fileInfos); // Respond with array of file information
  } catch (error) {
    console.error('Error reading directory:', error);
    res.status(500).json({ error: 'Failed to read directory' }); // Internal server error for directory reading failure
  }
});

/**
 * Ensures that the file path is correctly within the allowed videos directory.
 * Prevents directory traversal vulnerabilities.
 * @param {string} filePath - The file path to check.
 * @returns {string|null} - Corrected file path or null if invalid.
 */
function ensureCorrectFilePath(filePath) {
  const parts = filePath.split(path.sep);
  const videosIndex = parts.indexOf('videos');
  if (videosIndex === -1 || videosIndex === parts.length - 1) {
    return null; // Invalid path if 'videos' not found or is the last part
  }
  // Reconstruct the path starting from the 'videos' directory, ensuring it's within the intended base directory
  const correctedPath = path.join(videosDir, parts[videosIndex + 1], parts[parts.length - 1]);
  return correctedPath;
}

// Endpoint for watch page, serves HTML with video metadata
app.get('/watch/:token', async (req, res) => {
    const { token } = req.params; // Get token from URL parameter

    try {
        const [rows] = await pool.execute('SELECT file_path, user_email FROM file_tokens WHERE token = ?', [token]); // Fetch file path and user email from database

        if (rows.length === 0) {
            return res.status(404).sendFile(path.join(__dirname, 'public', 'TokenNotFound', 'tokennotfound.html')); // Send 404 page if token not found
        }

        const filePath = ensureCorrectFilePath(rows[0].file_path); // Ensure file path is valid and safe
        const fileName = path.basename(filePath, path.extname(filePath)); // Extract filename without extension
        const baseUrl = `${req.protocol}://${req.get('host')}`; // Construct base URL for video and thumbnail URLs

        // Metadata for HTML template, used for SEO and social sharing
        const metadata = {
            title: `${fileName} - Vidplo`,
            siteName: 'Vidplo',
            description: 'Watch and share videos on Vidplo',
            videoUrl: `${baseUrl}/api/video-content/${token}`, // URL to stream video content
            thumbnailUrl: `${baseUrl}/api/thumbnail/${token}`, // URL to get video thumbnail
            watchUrl: `${baseUrl}/watch/${token}` // URL of the watch page itself
        };
        const htmlTemplate = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf-8'); // Read HTML template file

        // Replace placeholders in HTML template with video metadata
        const htmlWithMetadata = htmlTemplate
            .replace('{{title}}', metadata.title)
            .replace('{{description}}', metadata.description)

            .replace('{{og:title}}', metadata.title)
            .replace('{{og:site_name}}', metadata.siteName)
            .replace('{{og:description}}', metadata.description)
            .replace('{{og:type}}', 'video.other')
            .replace('{{og:image}}', metadata.thumbnailUrl)
            .replace('{{og:url}}', metadata.watchUrl)
            .replace('{{og:video}}', metadata.videoUrl)
            .replace('{{og:video:url}}', metadata.videoUrl)
            .replace('{{og:video:secure_url}}', metadata.videoUrl.replace('http:', 'https:'))
            .replace('{{og:video:type}}', 'video/mp4')
            .replace('{{og:video:width}}', '1280')
            .replace('{{og:video:height}}', '720')

            .replace('{{twitter:card}}', 'player')
            .replace('{{twitter:title}}', metadata.title)
            .replace('{{twitter:description}}', metadata.description)
            .replace('{{twitter:image}}', metadata.thumbnailUrl)
            .replace('{{twitter:site}}', '@vidplo') // Replace with your twitter site if applicable
            .replace('{{twitter:url}}', metadata.watchUrl);

        res.send(htmlWithMetadata); // Send the HTML page with metadata
    } catch (error) {
        console.error('Error handling watch request:', error);
        res.status(500).json({ error: 'Internal server error' }); // Internal server error for watch page request failure
    }
});

// Endpoint to stream video content
app.get('/api/video-content/:token', async (req, res) => {
  const { token } = req.params; // Get token from URL parameter
  const { quality } = req.query; // Get quality parameter from query string
  const ipAddress = getClientIp(req); // Get client IP address

  try {
    // Check access permissions for the video
    const hasAccess = await checkVideoAccess(token, ipAddress);

    if (!hasAccess) {
      return res.status(403).json({
        error: 'Access denied. This video is private.' // Respond with 403 if access is denied
      });
    }

    // Get file path and encoded qualities from database
    const [rows] = await pool.execute(
      'SELECT file_path, encoded_qualities FROM file_tokens WHERE token = ?',
      [token]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' }); // Respond with 404 if video token is not found
    }

    let filePath = ensureCorrectFilePath(rows[0].file_path); // Ensure file path is valid
    const encodedQualities = JSON.parse(rows[0].encoded_qualities || '[]'); // Parse encoded qualities from database

    // Select video quality based on request and available qualities
    if (quality && encodedQualities.includes(quality)) {
      const fileName = path.basename(filePath, path.extname(filePath));
      filePath = path.join(path.dirname(filePath), `${fileName}_${quality}.mp4`); // Construct path for requested quality
    }

    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Video file not found' }); // Respond with 404 if video file is not found
    }

    // Stream video with range support for seeking
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range; // Get range header for seeking

    if (range) {
      // Handle range requests for seeking
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize-1;
      const chunksize = (end-start)+1;
      const file = fs.createReadStream(filePath, {start, end}); // Create read stream for the requested chunk
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': 'video/mp4',
      };
      res.writeHead(206, head); // Respond with 206 Partial Content for range requests
      file.pipe(res); // Pipe video chunk to response
    } else {
      // No range request, stream the entire video
      const head = {
        'Content-Length': fileSize,
        'Content-Type': 'video/mp4',
      };
      res.writeHead(200, head); // Respond with 200 OK for full video stream
      fs.createReadStream(filePath).pipe(res); // Pipe entire video file to response
    }

  } catch (error) {
    console.error('Error streaming video:', error);
    res.status(500).json({ error: 'Internal server error' }); // Internal server error for video streaming failure
  }
});

// Endpoint to get video information (filename, user plan, available qualities)
app.get('/api/video-info/:token', async (req, res) => {
  const { token } = req.params; // Get token from URL parameter

  try {
    const [rows] = await pool.execute('SELECT file_path, encoded_qualities FROM file_tokens WHERE token = ?', [token]); // Fetch file path and encoded qualities from database

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Invalid token' }); // Respond with 404 if token is invalid
    }

    const filePath = ensureCorrectFilePath(rows[0].file_path); // Ensure file path is valid

    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' }); // Respond with 404 if file is not found
    }

    const fileName = path.basename(filePath); // Extract filename
    const userEmail = path.basename(path.dirname(filePath)); // Extract user email from file path
    const userPlan = await getUserPlan(userEmail); // Get user plan to determine available features
    const encodedQualities = JSON.parse(rows[0].encoded_qualities || '[]'); // Parse encoded qualities

    res.json({ fileName, userPlan, availableQualities: encodedQualities }); // Respond with video info
  } catch (error) {
    console.error('Error fetching video info:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message }); // Internal server error for video info fetching failure
  }
});

/**
 * Retrieves user plan from the database based on user email.
 * @param {string} userEmail - User's email address.
 * @returns {Promise<string>} - User plan (e.g., 'Free', 'Premium'). Defaults to 'Free' if not found.
 */
async function getUserPlan(userEmail) {
  const query = 'SELECT plan FROM users WHERE email = ?';
  const [rows] = await pool.execute(query, [userEmail]); // Execute query to fetch user plan
  return rows.length > 0 ? rows[0].plan : 'Free'; // Return user plan or default to 'Free' if not found
}

// Endpoint to initiate video download (checks user plan and provides download URL)
app.get('/api/initiate-download/:token', async (req, res) => {
  const { token } = req.params; // Get token from URL parameter

  try {
    const [rows] = await pool.execute('SELECT file_path, user_email FROM file_tokens WHERE token = ?', [token]); // Fetch file path and user email from database

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Invalid token' }); // Respond with 404 if token is invalid
    }

    const filePath = ensureCorrectFilePath(rows[0].file_path); // Ensure file path is valid
    const userEmail = rows[0].user_email; // Get user email from database

    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' }); // Respond with 404 if file is not found
    }

    const userPlan = await getUserPlan(userEmail); // Get user plan to check download permissions

    if (userPlan === 'Free') {
      return res.status(403).json({ error: 'Download not allowed for Free tier users' }); // Respond with 403 if download is not allowed for Free plan
    }

    // For Premium and Custom users, provide the download URL
    const downloadUrl = `/api/download/${token}`;
    res.json({ downloadUrl }); // Respond with download URL
  } catch (error) {
    console.error('Error initiating download:', error);
    res.status(500).json({ error: 'Internal server error' }); // Internal server error for download initiation failure
  }
});

// Endpoint to download video content (actual file download)
app.get('/api/download/:token', async (req, res) => {
  const { token } = req.params; // Get token from URL parameter

  try {
      const [rows] = await pool.execute('SELECT file_path, user_email FROM file_tokens WHERE token = ?', [token]); // Fetch file path and user email from database

      if (rows.length === 0) {
      return res.status(404).json({ error: 'Invalid token' }); // Respond with 404 if token is invalid
      }

      const filePath = ensureCorrectFilePath(rows[0].file_path); // Ensure file path is valid
      const userEmail = rows[0].user_email; // Get user email from database

      if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' }); // Respond with 404 if file is not found
      }

      const userPlan = await getUserPlan(userEmail); // Get user plan to check download permissions

      if (userPlan === 'Free') {
      return res.status(403).json({ error: 'Download not allowed for Free tier users' }); // Respond with 403 if download is not allowed for Free plan
      }

      res.download(filePath); // Initiate file download
  } catch (error) {
      console.error('Error downloading file:', error);
      res.status(500).json({ error: 'Internal server error' }); // Internal server error for file download failure
  }
});

// Endpoint to get video thumbnail
app.get('/api/thumbnail/:token', async (req, res) => {
  const { token } = req.params; // Get token from URL parameter

  try {
    const [rows] = await pool.execute('SELECT file_path FROM file_tokens WHERE token = ?', [token]); // Fetch file path from database

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Thumbnail not found' }); // Respond with 404 if token is invalid (thumbnail not found indirectly)
    }

    const filePath = ensureCorrectFilePath(rows[0].file_path); // Ensure file path is valid
    if (!filePath) {
      return res.status(404).json({ error: 'Thumbnail file not found' }); // Respond with 404 if file path is invalid
    }

    const thumbnailPath = path.join(path.dirname(filePath), `${path.basename(filePath, path.extname(filePath))}_thumbnail.jpg`); // Construct thumbnail path

    if (!fs.existsSync(thumbnailPath)) {
      return res.status(404).json({ error: 'Thumbnail not found' }); // Respond with 404 if thumbnail file is not found
    }

    res.sendFile(thumbnailPath); // Send thumbnail file
  } catch (error) {
    console.error('Error serving thumbnail:', error);
    res.status(500).json({ error: 'Internal server error' }); // Internal server error for thumbnail serving failure
  }
});

// Endpoint to delete a file and associated resources (thumbnails, encoded versions, metadata)
app.delete('/delete-file', authenticateApiKey, async (req, res) => {
  const { token, userEmail } = req.body; // Get token and user email from request body

  if (!token || !userEmail) {
    return res.status(400).json({ error: 'Token and user email are required' }); // Respond with 400 if token or user email is missing
  }

  try {
    // Get file information from database using token and user email for verification
    const [rows] = await pool.execute(
      'SELECT file_path FROM file_tokens WHERE token = ? AND user_email = ?',
      [token, userEmail]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'File not found' }); // Respond with 404 if file not found for the given token and user email
    }

    const filePath = rows[0].file_path; // Get file path from database
    const fileName = path.basename(filePath); // Extract filename
    const fileBaseName = fileName.replace(/\.[^/.]+$/, ''); // Extract filename without extension
    const userDir = path.dirname(filePath); // Extract user directory

    // Array of files to be deleted (original, thumbnail, metadata, encoded versions)
    const qualities = ['144p', '360p', '480p', '720p'];
    const filesToDelete = [
      filePath, // Original file
      path.join(userDir, `${fileBaseName}_thumbnail.jpg`), // Thumbnail
      path.join(userDir, `${fileName}.json`), // Metadata file (adjust if backend metadata is stored differently)
      ...qualities.map(quality => path.join(userDir, `${fileBaseName}_${quality}.mp4`)) // Encoded versions
    ];

    // Delete all related files using Promise.all for parallel deletion
    await Promise.all(filesToDelete.map(file =>
      new Promise(resolve => {
        fs.unlink(file, err => {
          if (err && err.code !== 'ENOENT') {
            console.warn(`Warning: Failed to delete file ${file}:`, err); // Warn if deletion fails but ignore if file not found (ENOENT)
          }
          resolve(); // Resolve promise regardless of deletion success or file not found
        });
      })
    ));

    res.json({
      message: 'File deletion completed',
      details: {
        originalFile: fileName,
        deletedFiles: filesToDelete.map(f => path.basename(f)) // Respond with deletion success message and list of deleted files
      }
    });

  } catch (error) {
    console.error('Error during file deletion:', error);
    res.status(500).json({ error: 'Failed to delete file', details: error.message }); // Internal server error for file deletion failure
  }
});

// Endpoint to rename a file and update associated resources
app.post('/rename-file', authenticateApiKey, async (req, res) => {
  const { token, newFileName, userEmail } = req.body; // Get token, new filename, and user email from request body

  // Input validation
  if (!token || !newFileName || !userEmail) {
    return res.status(400).json({
      error: 'Missing required parameters',
      details: 'token, newFileName, and userEmail are required' // Respond with 400 if required parameters are missing
    });
  }

  try {
    // Get the original file information using token and user email for verification
    const [fileRows] = await pool.execute(
      'SELECT file_path FROM file_tokens WHERE token = ? AND user_email = ?',
      [token, userEmail]
    );

    if (fileRows.length === 0) {
      return res.status(404).json({ error: 'File not found' }); // Respond with 404 if file not found for the given token and user email
    }

    const oldPath = fileRows[0].file_path; // Get old file path from database
    const newPath = path.join(path.dirname(oldPath), newFileName); // Construct new file path with the new filename

    if (!fs.existsSync(oldPath)) {
      return res.status(404).json({ error: 'Source file not found' }); // Respond with 404 if original file not found
    }

    if (fs.existsSync(newPath)) {
      return res.status(400).json({ error: 'A file with the new name already exists' }); // Respond with 400 if file with new name already exists
    }

    // Update the database with the new file path
    await pool.execute(
      'UPDATE file_tokens SET file_path = ? WHERE token = ?',
      [newPath, token]
    );

    // Rename the main file
    fs.renameSync(oldPath, newPath);

    // Rename encoded versions and thumbnail to match the new filename
    const qualities = ['144p', '360p', '480p', '720p'];
    const oldBaseName = path.basename(oldPath, path.extname(oldPath)); // Extract old base filename
    const newBaseName = path.basename(newFileName, path.extname(newFileName)); // Extract new base filename

    // Notify backend metadata service about file rename to update metadata
    try {
      await axios.post(`${process.env.BACKEND_SERVER_URL}/create-metadata`, {
        fileName: newFileName,
        userEmail,
        token,
        updateExisting: true  // Flag to indicate this is a rename operation
      }, {
        headers: {
          'Authorization': `Bearer ${process.env.API_KEY}` // Pass API key for backend service authentication
        }
      });
    } catch (metadataError) {
      console.error('Error notifying backend about file rename:', metadataError);
      // Continue with the rest of the rename operation even if metadata update fails (non-critical)
    }

    // Rename encoded versions
    qualities.forEach(quality => {
      const oldEncodedPath = path.join(path.dirname(oldPath), `${oldBaseName}_${quality}.mp4`);
      const newEncodedPath = path.join(path.dirname(newPath), `${newBaseName}_${quality}.mp4`);
      if (fs.existsSync(oldEncodedPath)) {
        fs.renameSync(oldEncodedPath, newEncodedPath); // Rename encoded version if it exists
      }
    });

    // Rename thumbnail
    const oldThumbnailPath = path.join(path.dirname(oldPath), `${oldBaseName}_thumbnail.jpg`);
    const newThumbnailPath = path.join(path.dirname(newPath), `${newBaseName}_thumbnail.jpg`);
    if (fs.existsSync(oldThumbnailPath)) {
      fs.renameSync(oldThumbnailPath, newThumbnailPath); // Rename thumbnail if it exists
    }

    res.json({
      message: 'File renamed successfully',
      newFileName,
      token,
      newPath,
      details: {
        renamedFiles: [
          newFileName,
          `${newBaseName}_thumbnail.jpg`,
          ...qualities.map(quality => `${newBaseName}_${quality}.mp4`)
        ].filter(file => fs.existsSync(path.join(path.dirname(newPath), file))) // Respond with success message and list of renamed files
      }
    });

  } catch (error) {
    console.error('Error during file rename:', error);
    res.status(500).json({ error: 'Failed to rename file', details: error.message }); // Internal server error for file rename failure
  }
});

// Endpoint to delete a thumbnail (requires a separate API key for deletion requests - potentially for internal/admin use)
// Consider removing this or securing it further for open-source release if not intended for public use.
app.delete('/request/delete-thumbnail/:token/:apiKey', async (req, res) => {
  const { token, apiKey } = req.params; // Get token and apiKey from URL parameters
  const DELETE_API_KEY = process.env.DELETE_API_KEY; // Load delete API key from environment variable

  if (apiKey !== DELETE_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' }); // Respond with 401 if delete API key is invalid
  }

  try {
    const query = 'SELECT file_path, user_email FROM file_tokens WHERE token = ?';
    const [rows] = await pool.execute(query, [token]); // Fetch file path and user email from database

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Token not found' }); // Respond with 404 if token is not found
    }

    const { file_path: filePath, user_email: userEmail } = rows[0]; // Extract file path and user email
    const fileName = path.basename(filePath); // Extract filename
    const thumbnailName = fileName.replace(/\.[^/.]+$/, "_thumbnail.jpg"); // Construct thumbnail filename
    const thumbnailPath = path.join(videosDir, userEmail, thumbnailName); // Construct full thumbnail path

    if (fs.existsSync(thumbnailPath)) {
      fs.unlinkSync(thumbnailPath); // Delete thumbnail file if it exists
      console.log(`Thumbnail deleted: ${thumbnailPath}`);
      res.json({ message: 'Thumbnail deleted successfully' }); // Respond with success message
    } else {
      console.log(`Thumbnail not found: ${thumbnailPath}`);
      res.status(404).json({ error: 'Thumbnail not found' }); // Respond with 404 if thumbnail file is not found
    }
  } catch (error) {
    console.error('Error processing thumbnail deletion:', error);
    res.status(500).json({ error: 'Failed to process thumbnail deletion' }); // Internal server error for thumbnail deletion failure
  }
});

// 404 handler for any other routes not defined
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404', '404.html')); // Send 404 HTML page for undefined routes
});

/**
 * Starts the server after initializing the database connection.
 */
async function startServer() {
  await initializeDatabase(); // Initialize database connection pool

  app.listen(PORT, () => {
    console.log(`Server listening at ${PORT}`); // Start server and log port
  });
}

// Start the server
startServer().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1); // Exit process if server fails to start
});