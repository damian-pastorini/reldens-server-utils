# API Reference

Complete API documentation for @reldens/server-utils classes.

## Core Classes

### FileHandler
`lib/file-handler.js`

Singleton wrapper for Node.js fs and path modules. Used instead of direct require('fs') or require('path') throughout Reldens.

**File Operations:**
- `exists(filePath)` - Check if file/directory exists
- `readFile(filePath)` - Read file contents
- `writeFile(filePath, content)` - Write file
- `createFolder(folderPath)` - Create directory recursively
- `remove(fullPath)` - Remove file/folder recursively
- `copyFile(from, to)` - Copy file
- `copyFolderSync(from, to)` - Copy folder recursively
- `moveFile(from, to)` - Move/rename file

**Path Operations:**
- `joinPaths(...paths)` - Join path segments
- `getFileName(filePath)` - Get file name (basename)
- `getFolderName(filePath)` - Get directory name (dirname)
- `getRelativePath(from, to)` - Calculate relative path
- `normalizePath(filePath)` - Normalize path
- `isAbsolutePath(filePath)` - Check if path is absolute

**File Inspection:**
- `isFile(filePath)` - Check if path is a file
- `isFolder(dirPath)` - Check if path is a folder
- `getFileSize(filePath)` - Get file size in bytes
- `getFileStats(filePath)` - Get file stats
- `getFilesInFolder(dirPath, extensions)` - List files with optional filtering
- `fetchSubFoldersList(folder, options)` - Get subfolder list

**JSON Operations:**
- `fetchFileJson(filePath)` - Read and parse JSON file
- `isValidJson(filePath)` - Validate JSON file

**Security Features:**
- `generateSecureFilename(originalName)` - Generate secure random filename
- `validateFileType(filePath, type, allowedTypes, maxSize)` - Validate file
- `detectFileType(filePath)` - Detect MIME type from magic numbers
- `quarantineFile(filePath, reason)` - Move suspicious file to quarantine
- `isValidPath(filePath)` - Validate path for security
- `sanitizePath(filePath)` - Sanitize path string

**Advanced Operations:**
- `walkDirectory(dirPath, callback)` - Recursively process directory tree
- `getDirectorySize(dirPath)` - Calculate total directory size
- `emptyDirectory(dirPath)` - Remove all contents from directory
- `compareFiles(file1, file2)` - Compare file contents
- `appendToFile(filePath, content)` - Append to file
- `prependToFile(filePath, content)` - Prepend to file
- `replaceInFile(filePath, searchValue, replaceValue)` - Replace in file
- `createReadStream(filePath, options)` - Create readable stream for file
- `getFileModificationTime(filePath)` - Get file last modification time

**Important:**
- All methods include built-in error handling, no need for try/catch
- DO NOT use FileHandler.exists to validate other FileHandler methods
- DO NOT enclose FileHandler methods in try/catch blocks

### AppServerFactory
`lib/app-server-factory.js`

Creates Express app servers with modular security components. Supports HTTP, HTTPS, HTTP/2.

**Features:**
- Virtual host management with SNI support
- HTTP/2 CDN server integration
- Reverse proxy with WebSocket support
- Development mode detection and configuration
- Request logging middleware
- Lifecycle event dispatching

**Configuration Properties:**
- `http2CdnDomains` - Array of domain configurations for HTTP/2 CDN multi-certificate SNI (optional)
- `onError` - Custom error handler callback for server errors
- `onRequestSuccess` - Callback for successful requests
- `onRequestError` - Callback for failed requests
- `onEvent` - Callback for lifecycle events

**Methods:**
- `createAppServer(config)` - Create and configure server
- `createHttp2CdnServer()` - Create HTTP/2 CDN server with optional multi-cert SNI
- `addDomain(domainConfig)` - Add virtual host domain
- `addDevelopmentDomain(domain)` - Add development domain
- `dispatch(eventName, eventData)` - Dispatch lifecycle event (wrapper for EventDispatcher)
- `handleError(errorType, error, context)` - Handle and log error (wrapper for ServerErrorHandler)
- `enableServeHome(app, callback)` - Enable homepage serving
- `serveStatics(app, staticPath)` - Serve static files
- `enableCSP(cspOptions)` - Enable Content Security Policy
- `listen(port)` - Start server listening
- `close()` - Gracefully close server

**Security Configurers:**
- `DevelopmentModeDetector` - Auto-detect development environment
- `ProtocolEnforcer` - HTTP/HTTPS protocol enforcement
- `SecurityConfigurer` - Helmet integration and XSS protection
- `CorsConfigurer` - CORS with dynamic origin validation
- `RateLimitConfigurer` - Global and endpoint-specific rate limiting
- `ReverseProxyConfigurer` - Domain-based reverse proxy

### Encryptor
`lib/encryptor.js`

Singleton for cryptographic operations.

**Password Hashing:**
- `encryptPassword(password)` - Hash password with PBKDF2 (100k iterations, SHA-512)
- `validatePassword(password, storedPassword)` - Validate password against hash

**Data Encryption:**
- `encryptData(data, key)` - Encrypt data with AES-256-GCM
- `decryptData(encryptedData, key)` - Decrypt AES-256-GCM data
- `generateSecretKey()` - Generate 256-bit secret key

**Token Generation:**
- `generateSecureToken(length)` - Generate cryptographically secure token
- `generateTOTP(secret, timeStep)` - Generate time-based OTP

**Hashing and Verification:**
- `hashData(data, algorithm)` - Hash with SHA-256, SHA-512, or MD5
- `generateHMAC(data, secret, algorithm)` - Generate HMAC signature
- `verifyHMAC(data, secret, signature, algorithm)` - Verify HMAC signature
- `constantTimeCompare(a, b)` - Constant-time string comparison

### UploaderFactory
`lib/uploader-factory.js`

File upload handling with Multer.

**Security Validation:**
- Filename security validation
- MIME type validation
- File extension validation
- File size validation
- Content validation using magic numbers
- Dangerous extension filtering

**Features:**
- Multiple file upload support with field mapping
- Secure filename generation option
- Automatic cleanup on validation failure
- Custom error response handling
- Per-field destination mapping

**Methods:**
- `createUploader(fields, buckets, allowedFileTypes)` - Create upload middleware
- `validateFilenameSecurity(filename)` - Validate filename
- `validateFile(file, allowedType, callback)` - Validate during upload
- `validateFileContents(file, allowedType)` - Validate after upload
- `convertToRegex(key)` - Convert MIME type patterns to regex

### Http2CdnServer
`lib/http2-cdn-server.js`

HTTP/2 secure server for CDN-like static file serving.

**Features:**
- Multi-certificate SNI support for multiple domains
- Optimized for CSS, JavaScript, images, and fonts
- Dynamic CORS origin validation with regex pattern support
- Configurable cache headers per file extension
- Comprehensive MIME type detection
- HTTP/1.1 fallback support
- Security headers (X-Content-Type-Options, X-Frame-Options, Vary)
- Query string stripping for cache optimization
- Comprehensive error handling (server, TLS, session, stream errors)

**Configuration Properties:**
- `domains` - Array of domain configurations for multi-certificate SNI (optional)
- `keyPath` - Path to SSL key file (backward compatibility, single cert mode)
- `certPath` - Path to SSL certificate file (backward compatibility, single cert mode)
- `onError` - Custom error handler callback for server errors
- `onRequestSuccess` - Callback for successful requests
- `onRequestError` - Callback for failed requests
- `onEvent` - Callback for lifecycle events

**Multi-Certificate Configuration Example:**
```javascript
domains: [
    {hostname: 'cdn.domain1.com', keyPath: '/path/to/key1.pem', certPath: '/path/to/cert1.pem'},
    {hostname: 'cdn.domain2.com', keyPath: '/path/to/key2.pem', certPath: '/path/to/cert2.pem'}
]
```

**Methods:**
- `create()` - Create HTTP/2 secure server with SNI support
- `listen()` - Start listening on configured port
- `close()` - Gracefully close server
- `dispatch(eventName, eventData)` - Dispatch lifecycle event (wrapper for EventDispatcher)
- `handleError(errorType, error, context)` - Handle and log error (wrapper for ServerErrorHandler)
- `handleStream(stream, headers)` - Handle HTTP/2 stream
- `handleHttp1Request(req, res)` - Handle HTTP/1.1 fallback requests
- `resolveFilePath(requestPath)` - Resolve file path from request
- `setupEventHandlers()` - Configure server error event handlers
- `setupDomainConfiguration()` - Configure single or multi-certificate mode
- `validateCertificates()` - Validate all domain certificates exist
- `buildSniContexts()` - Build TLS contexts for each domain
- `getSniCallback()` - Get SNI callback for certificate selection
- `buildServerOptions()` - Build HTTP/2 server options with SNI support

## Utility Classes

### RequestLogger
`lib/request-logger.js`

Express middleware for request logging.

**Methods:**
- `createMiddleware(onRequestSuccess, onRequestError)` - Create logging middleware

Tracks request timing and invokes callbacks based on status code:
- Status < 400: calls onRequestSuccess
- Status >= 400: calls onRequestError

### EventDispatcher
`lib/event-dispatcher.js`

Static utility for dispatching lifecycle events.

**Methods:**
- `dispatch(onEventCallback, eventType, instanceName, instance, data)` - Dispatch event

Validates callback exists before invoking with structured event data.

### ServerErrorHandler
`lib/server-error-handler.js`

Centralized error handling for all server components.

**Methods:**
- `handleError(onErrorCallback, instanceName, instance, key, error, context)` - Handle and delegate errors

Used by Http2CdnServer, AppServerFactory, and ReverseProxyConfigurer. Provides structured error context with instance details and metadata.

### ServerDefaultConfigurations
`lib/server-default-configurations.js`

Static class providing default configurations.

**Properties:**
- `mimeTypes` - Comprehensive MIME type mappings for common file extensions
- `cacheConfig` - Default cache max-age settings (1 year for CSS/JS/fonts, 30 days for images)

### ServerFactoryUtils
`lib/server-factory-utils.js`

Static utility methods for server operations.

**Methods:**
- `getCacheConfigForPath(path, cacheConfig)` - Get cache config for file path
- `validateOrigin(origin, corsOrigins, corsAllowAll)` - Validate CORS origin (supports strings and RegExp)
- `stripQueryString(url)` - Remove query string from URL

### ServerHeaders
`lib/server-headers.js`

Centralized header management.

**Headers:**
- HTTP/2 headers configuration
- Express security headers
- Cache control headers
- Proxy forwarding headers

**Methods:**
- `buildCacheControlHeader(maxAge)` - Build cache control header string

## Security Configurers

Located in `lib/app-server-factory/`

### DevelopmentModeDetector
`development-mode-detector.js`

Auto-detects development environment.

**Methods:**
- `detect(config)` - Detect if in development mode
- `matchesPattern(domain)` - Check if domain matches development pattern

Checks NODE_ENV, domain patterns, and configured domains. Built-in patterns: localhost, 127.0.0.1, .local, .test, .dev, .staging, etc.

### ProtocolEnforcer
`protocol-enforcer.js`

Enforces HTTP/HTTPS protocol consistency.

**Methods:**
- `setup(app, config)` - Setup protocol enforcement middleware

Development mode awareness with automatic redirects when protocol doesn't match configuration.

### SecurityConfigurer
`security-configurer.js`

Helmet integration with CSP management.

**Methods:**
- `setupHelmet(app, config)` - Setup Helmet middleware
- `setupXssProtection(app, config)` - Setup XSS protection
- `enableCSP(app, cspOptions)` - Enable Content Security Policy
- `addExternalDomainsToCsp(directives, externalDomains)` - Add external domains to CSP

Features XSS protection with request body sanitization. Development-friendly CSP configuration with directive merging or override support.

### CorsConfigurer
`cors-configurer.js`

Dynamic CORS origin validation.

**Methods:**
- `setup(app, config)` - Setup CORS middleware
- `extractDevelopmentOrigins(domainMapping)` - Extract development origins
- `normalizeHost(originOrHost)` - Normalize host string

Development domain support with automatic port variations. Credential support configuration.

### RateLimitConfigurer
`rate-limit-configurer.js`

Global and endpoint-specific rate limiting.

**Methods:**
- `setup(app, config)` - Setup global rate limiting
- `createHomeLimiter()` - Create homepage-specific limiter

Development mode multiplier for lenient limits. IP-based key generation option.

### ReverseProxyConfigurer
`reverse-proxy-configurer.js`

Domain-based reverse proxy routing.

**Methods:**
- `setup(app, config)` - Setup reverse proxy
- `createProxyMiddleware(rule)` - Create proxy middleware for rule
- `handleProxyError(err, req, res)` - Handle proxy errors with status codes
- `validateProxyRule(rule)` - Validate proxy rule configuration
- `extractHostname(req)` - Extract hostname from request

**Features:**
- WebSocket support
- SSL termination
- Header preservation (X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host)
- Virtual host integration
- Comprehensive error handling:
  - 502 Bad Gateway for ECONNREFUSED errors
  - 504 Gateway Timeout for ETIMEDOUT/ESOCKETTIMEDOUT errors
  - 500 Internal Server Error for other proxy errors
- Custom error callback support via ServerErrorHandler
