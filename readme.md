# Vidplo Storage - Open Source Video Platform Backend

This is the Storage service for Vidplo, a video platform. It handles video uploads, encoding, storage, streaming, and management. This code is designed to be open-source, allowing for community contributions and customization.

## Features

- **Video Uploads:** Accepts video uploads with user email association.
- **Video Encoding:** Encodes videos into multiple resolutions (144p, 360p, 480p, 720p) for adaptive streaming, with quality levels depending on user plans (Free/Premium).
- **Thumbnail Generation:** Automatically generates thumbnails for uploaded videos.
- **Token-Based Access:** Uses tokens for secure video access, streaming, and management.
- **Video Streaming:** Streams video content with range requests for efficient seeking.
- **Video Information API:** Provides API endpoints to retrieve video metadata and encoding status.
- **Download Management:** Supports video downloads for premium users.
- **File Management:** Includes API endpoints for file deletion and renaming.
- **API Key Authentication:** Secures storage endpoints with API key authentication.
- **CORS Support:** Configurable CORS to allow access from specified frontend origins.
- **MySQL Database:** Uses MySQL for storing video metadata and user information.

## Setup Instructions

### Prerequisites

- [Node.js](https://nodejs.org/) (>= v14)
- [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)
- [MySQL Database](https://www.mysql.com/)
- [ffmpeg](https://ffmpeg.org/) - Make sure ffmpeg is installed on your system and accessible in your PATH.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Viola-Network/Vidplo-Storage-OS
   cd Vidplo-Storage-OS
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

### Configuration

1. **Environment Variables:**
   - Create a `.env` file in the root directory of the project based on the provided `.env.example` file.
   - Fill in the placeholder values in `.env` with your actual configuration details.

   ```
   PORT=3000 # Port for the server to listen on
   API_KEY=YOUR_API_KEY # API key for storage security
   VIDEOS_DIR=./uploads/videos # Directory for video storage

   # MySQL Database Configuration
   DB_HOST=YOUR_DB_HOST
   DB_PORT=3306
   DB_NAME=YOUR_DB_NAME
   DB_USER=YOUR_DB_USER
   DB_PASSWORD=YOUR_DB_PASSWORD

   # CORS Configuration
   CORS_ALLOWED_ORIGINS=http://localhost:3000,https://yourfrontenddomain.com

   # Backend Metadata Service URL (Optional, if you have a separate metadata service)
   BACKEND_SERVER_URL=http://your-metadata-service.com

   # Optional Delete API Key (Use with caution)
   # DELETE_API_KEY=YOUR_DELETE_API_KEY
   ```

2. **Database Setup:**
   - Ensure you have a MySQL database server running.
   - Create a database named as specified in `DB_NAME` in your `.env` file.
   - Create a user with the username and password specified in `DB_USER` and `DB_PASSWORD` and grant necessary permissions to the database.
   - The database schema includes tables like `file_tokens`, `file_meta`, `users`, and `website_sessions`. You will need to create these tables. (Schema details can be inferred from the `server.js` code). Example schema SQL (Conceptual):

     ```sql
     -- Example Schema (Conceptual - Refer to server.js for exact table structures)
     CREATE TABLE file_tokens (
         token VARCHAR(255) PRIMARY KEY,
         file_path VARCHAR(255),
         user_email VARCHAR(255),
         file_size INT,
         encoded_qualities JSON
     );

     CREATE TABLE file_meta (
         token VARCHAR(255) PRIMARY KEY,
         views INT DEFAULT 0,
         views_ip JSON,
         privacy ENUM('public', 'private') DEFAULT 'public'
     );

     CREATE TABLE users (
         id INT AUTO_INCREMENT PRIMARY KEY,
         email VARCHAR(255) UNIQUE,
         plan VARCHAR(50) DEFAULT 'Free'
     );

     CREATE TABLE website_sessions (
         id INT AUTO_INCREMENT PRIMARY KEY,
         user_id INT,
         ip_address VARCHAR(45),
         last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
         FOREIGN KEY (user_id) REFERENCES users(id)
     );
     ```

### Running the Server

```bash
npm start
```

The server will start at the port specified in your `.env` file or default to 3000.

## API Endpoints

**Base URL:** `http://your-server-domain:[PORT]` (or `http://localhost:3000` for local development)

| Endpoint                        | Method | Request Body                                  | Response Format | Authentication | Description                                    |
|---------------------------------|--------|-----------------------------------------------|-----------------|----------------|------------------------------------------------|
| `/receive`                      | POST   | `multipart/form-data`: `file`, `userEmail`   | JSON            | API Key        | Upload a video file.                             |
| `/api/record-view/:token`       | POST   | None                                          | JSON            | Public         | Record a video view.                             |
| `/api/encoding-status/:token`    | GET    | None                                          | JSON            | Public         | Get video encoding status.                       |
| `/register-token`              | POST   | JSON: `{token, filePath, userEmail, fileSize}` | JSON            | API Key        | Register a pre-existing video token.             |
| `/request-token`               | POST   | JSON: `{filePath, userEmail}`                 | JSON            | API Key        | Request a token for an existing file.            |
| `/files`                         | GET    | Query: `userEmail`                            | JSON            | API Key        | List files for a user.                           |
| `/watch/:token`                  | GET    | None                                          | HTML            | Public         | Watch video page (HTML).                         |
| `/api/video-content/:token`      | GET    | Query: `quality` (optional)                   | Video Stream    | Public/Private | Stream video content.                             |
| `/api/video-info/:token`         | GET    | None                                          | JSON            | Public         | Get video information.                           |
| `/api/initiate-download/:token` | GET    | None                                          | JSON            | Public         | Initiate video download (get download URL).      |
| `/api/download/:token`           | GET    | None                                          | File Download   | Public/Private | Download video file.                             |
| `/api/thumbnail/:token`        | GET    | None                                          | Image (JPEG)    | Public         | Get video thumbnail.                             |
| `/delete-file`                   | DELETE | JSON: `{token, userEmail}`                    | JSON            | API Key        | Delete a video file and associated resources.    |
| `/rename-file`                   | POST   | JSON: `{token, newFileName, userEmail}`       | JSON            | API Key        | Rename a video file and associated resources.    |

**Authentication:**

- Endpoints marked with "API Key" require a valid API key to be included in the `Authorization` header as a Bearer token.
  Example Header: `Authorization: Bearer YOUR_API_KEY`

**Error Responses:**

- API endpoints generally return JSON responses with an `error` field for error conditions.
- HTTP status codes are used to indicate the type of error (e.g., 400 for bad request, 401 for unauthorized, 404 for not found, 500 for internal server error).

## License

[MIT License](LICENSE)
