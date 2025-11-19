# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Package Overview

**@reldens/server-utils** is a core utility package for server-side operations in Reldens. It provides:
- File system operations (FileHandler)
- HTTP/HTTPS server creation (AppServerFactory)
- File encryption (Encryptor)
- File upload handling (UploaderFactory)
- HTTP/2 CDN server (Http2CdnServer)
- Server configuration utilities

## Key Commands

```bash
# Run tests (if configured)
npm test
```

## Architecture

### Core Classes

**FileHandler** (`lib/file-handler.js`):
- Singleton wrapper for Node.js fs and path modules
- Used instead of direct require('fs') or require('path') throughout Reldens
- Key file operations:
  - `exists(filePath)` - Check if file/directory exists
  - `readFile(filePath)` - Read file contents
  - `writeFile(filePath, content)` - Write file
  - `createFolder(folderPath)` - Create directory recursively
  - `remove(fullPath)` - Remove file/folder recursively
  - `copyFile(from, to)` - Copy file
  - `copyFolderSync(from, to)` - Copy folder recursively
  - `moveFile(from, to)` - Move/rename file
- Path operations:
  - `joinPaths(...paths)` - Join path segments
  - `getFileName(filePath)` - Get file name (basename)
  - `getFolderName(filePath)` - Get directory name (dirname)
  - `getRelativePath(from, to)` - Calculate relative path
  - `normalizePath(filePath)` - Normalize path
  - `isAbsolutePath(filePath)` - Check if path is absolute
- File inspection:
  - `isFile(filePath)` - Check if path is a file
  - `isFolder(dirPath)` - Check if path is a folder
  - `getFileSize(filePath)` - Get file size in bytes
  - `getFileStats(filePath)` - Get file stats
  - `getFilesInFolder(dirPath, extensions)` - List files with optional filtering
  - `fetchSubFoldersList(folder, options)` - Get subfolder list
- JSON operations:
  - `fetchFileJson(filePath)` - Read and parse JSON file
  - `isValidJson(filePath)` - Validate JSON file
- Security features:
  - `generateSecureFilename(originalName)` - Generate secure random filename
  - `validateFileType(filePath, type, allowedTypes, maxSize)` - Validate file
  - `detectFileType(filePath)` - Detect MIME type from magic numbers
  - `quarantineFile(filePath, reason)` - Move suspicious file to quarantine
  - `isValidPath(filePath)` - Validate path for security
  - `sanitizePath(filePath)` - Sanitize path string
- Advanced operations:
  - `walkDirectory(dirPath, callback)` - Recursively process directory tree
  - `getDirectorySize(dirPath)` - Calculate total directory size
  - `emptyDirectory(dirPath)` - Remove all contents from directory
  - `compareFiles(file1, file2)` - Compare file contents
  - `appendToFile(filePath, content)` - Append to file
  - `prependToFile(filePath, content)` - Prepend to file
  - `replaceInFile(filePath, searchValue, replaceValue)` - Replace in file
- All methods include built-in error handling, no need for try/catch
- DO NOT use FileHandler.exists to validate other FileHandler methods
- DO NOT enclose FileHandler methods in try/catch blocks

**AppServerFactory** (`lib/app-server-factory.js`):
- Creates Express app servers with modular security components
- Supports HTTP, HTTPS, HTTP/2
- Key features:
  - Virtual host management with SNI support
  - HTTP/2 CDN server integration
  - Reverse proxy with WebSocket support
  - Development mode detection and configuration
- Security configurers (modular):
  - `DevelopmentModeDetector` - Auto-detect development environment
  - `ProtocolEnforcer` - HTTP/HTTPS protocol enforcement
  - `SecurityConfigurer` - Helmet integration and XSS protection
  - `CorsConfigurer` - CORS with dynamic origin validation
  - `RateLimitConfigurer` - Global and endpoint-specific rate limiting
  - `ReverseProxyConfigurer` - Domain-based reverse proxy
- Methods:
  - `createAppServer(config)` - Create and configure server
  - `addDomain(domainConfig)` - Add virtual host domain
  - `addDevelopmentDomain(domain)` - Add development domain
  - `enableServeHome(app, callback)` - Enable homepage serving
  - `serveStatics(app, staticPath)` - Serve static files
  - `enableCSP(cspOptions)` - Enable Content Security Policy
  - `listen(port)` - Start server listening
  - `close()` - Gracefully close server

**Encryptor** (`lib/encryptor.js`):
- Singleton for cryptographic operations
- Password hashing:
  - `encryptPassword(password)` - Hash password with PBKDF2 (100k iterations, SHA-512)
  - `validatePassword(password, storedPassword)` - Validate password against hash
- Data encryption:
  - `encryptData(data, key)` - Encrypt data with AES-256-GCM
  - `decryptData(encryptedData, key)` - Decrypt AES-256-GCM data
  - `generateSecretKey()` - Generate 256-bit secret key
- Token generation:
  - `generateSecureToken(length)` - Generate cryptographically secure token
  - `generateTOTP(secret, timeStep)` - Generate time-based OTP
- Hashing and verification:
  - `hashData(data, algorithm)` - Hash with SHA-256, SHA-512, or MD5
  - `generateHMAC(data, secret, algorithm)` - Generate HMAC signature
  - `verifyHMAC(data, secret, signature, algorithm)` - Verify HMAC signature
  - `constantTimeCompare(a, b)` - Constant-time string comparison

**UploaderFactory** (`lib/uploader-factory.js`):
- File upload handling with Multer
- Multi-level security validation:
  - Filename security validation
  - MIME type validation
  - File extension validation
  - File size validation
  - Content validation using magic numbers
  - Dangerous extension filtering
- Features:
  - Multiple file upload support with field mapping
  - Secure filename generation option
  - Automatic cleanup on validation failure
  - Custom error response handling
  - Per-field destination mapping
- Methods:
  - `createUploader(fields, buckets, allowedFileTypes)` - Create upload middleware
  - `validateFilenameSecurity(filename)` - Validate filename
  - `validateFile(file, allowedType, callback)` - Validate during upload
  - `validateFileContents(file, allowedType)` - Validate after upload
  - `convertToRegex(key)` - Convert MIME type patterns to regex

**Http2CdnServer** (`lib/http2-cdn-server.js`):
- HTTP/2 secure server for CDN-like static file serving
- Features:
  - Optimized for CSS, JavaScript, images, and fonts
  - Dynamic CORS origin validation with regex pattern support
  - Configurable cache headers per file extension
  - Comprehensive MIME type detection
  - HTTP/1.1 fallback support
  - Security headers (X-Content-Type-Options, X-Frame-Options, Vary)
  - Query string stripping for cache optimization
- Methods:
  - `create()` - Create HTTP/2 secure server
  - `listen()` - Start listening on configured port
  - `close()` - Gracefully close server
  - `handleStream(stream, headers)` - Handle HTTP/2 stream
  - `resolveFilePath(requestPath)` - Resolve file path from request

### Utility Classes

**ServerDefaultConfigurations** (`lib/server-default-configurations.js`):
- Static class providing default configurations
- `mimeTypes` - Comprehensive MIME type mappings for common file extensions
- `cacheConfig` - Default cache max-age settings (1 year for CSS/JS/fonts, 30 days for images)

**ServerFactoryUtils** (`lib/server-factory-utils.js`):
- Static utility methods for server operations
- `getCacheConfigForPath(path, cacheConfig)` - Get cache config for file path
- `validateOrigin(origin, corsOrigins, corsAllowAll)` - Validate CORS origin (supports strings and RegExp)
- `stripQueryString(url)` - Remove query string from URL

**ServerHeaders** (`lib/server-headers.js`):
- Centralized header management
- HTTP/2 headers configuration
- Express security headers
- Cache control headers
- Proxy forwarding headers
- `buildCacheControlHeader(maxAge)` - Build cache control header string

### Security Configurers (in `lib/app-server-factory/`)

**DevelopmentModeDetector** (`development-mode-detector.js`):
- Auto-detects development environment
- Checks NODE_ENV, domain patterns, and configured domains
- Built-in patterns: localhost, 127.0.0.1, .local, .test, .dev, .staging, etc.
- `detect(config)` - Detect if in development mode
- `matchesPattern(domain)` - Check if domain matches development pattern

**ProtocolEnforcer** (`protocol-enforcer.js`):
- Enforces HTTP/HTTPS protocol consistency
- Development mode awareness
- Automatic redirects when protocol doesn't match configuration
- `setup(app, config)` - Setup protocol enforcement middleware

**SecurityConfigurer** (`security-configurer.js`):
- Helmet integration with CSP management
- XSS protection with request body sanitization
- Development-friendly CSP configuration
- Supports CSP directive merging or override
- `setupHelmet(app, config)` - Setup Helmet middleware
- `setupXssProtection(app, config)` - Setup XSS protection
- `enableCSP(app, cspOptions)` - Enable Content Security Policy
- `addExternalDomainsToCsp(directives, externalDomains)` - Add external domains to CSP

**CorsConfigurer** (`cors-configurer.js`):
- Dynamic CORS origin validation
- Development domain support with automatic port variations
- Credential support configuration
- `setup(app, config)` - Setup CORS middleware
- `extractDevelopmentOrigins(domainMapping)` - Extract development origins
- `normalizeHost(originOrHost)` - Normalize host string

**RateLimitConfigurer** (`rate-limit-configurer.js`):
- Global and endpoint-specific rate limiting
- Development mode multiplier for lenient limits
- IP-based key generation option
- `setup(app, config)` - Setup global rate limiting
- `createHomeLimiter()` - Create homepage-specific limiter

**ReverseProxyConfigurer** (`reverse-proxy-configurer.js`):
- Domain-based reverse proxy routing
- WebSocket support
- SSL termination
- Header preservation (X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host)
- Virtual host integration
- Graceful error handling (502 Bad Gateway, 504 Gateway Timeout)
- `setup(app, config)` - Setup reverse proxy
- `createProxyMiddleware(rule)` - Create proxy middleware for rule
- `handleProxyError(err, req, res)` - Handle proxy errors

## Important Notes

- **ALWAYS use FileHandler** instead of Node.js fs/path modules
- FileHandler methods have built-in error handling - no try/catch needed
- DO NOT enclose FileHandler methods in try/catch blocks
- DO NOT use FileHandler.exists to validate other FileHandler methods (e.g., before createFolder)
- AppServerFactory handles all Express server configuration
- All server utilities support both HTTP and HTTPS
