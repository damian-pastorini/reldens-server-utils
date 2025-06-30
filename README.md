# Reldens - Server Utils

A Node.js server toolkit providing secure application server creation, file handling, encryption, and file upload capabilities for production-ready applications.

[![Reldens - GitHub - Release](https://www.dwdeveloper.com/media/reldens/reldens-mmorpg-platform.png)](https://github.com/damian-pastorini/reldens)

## Features

### AppServerFactory
- Complete Express.js server configuration with security defaults
- HTTPS/HTTP server creation with SSL certificate management
- SNI (Server Name Indication) support for multi-domain hosting
- Virtual host management with domain mapping
- Development mode detection with appropriate configurations
- CORS configuration with flexible origin management
- Rate limiting with customizable thresholds
- Security headers and XSS protection
- Helmet integration for enhanced security
- Protocol enforcement (HTTP to HTTPS redirection)
- Trusted proxy configuration
- Request parsing with size limits and validation
- Static file serving with security headers
- Input validation utilities

### FileHandler
- Secure file system operations with path validation
- File and folder creation, copying, and removal
- JSON file parsing and validation
- File type detection based on magic numbers
- Secure filename generation
- Path sanitization and traversal protection
- File permissions checking
- Folder content listing and filtering
- Temporary file creation
- File quarantine functionality for security threats
- Binary file head reading for type detection
- Comprehensive error handling with detailed context

### Encryptor
- Password hashing using PBKDF2 with configurable iterations
- Password validation against stored hashes
- AES-256-GCM data encryption and decryption
- Secure token generation with customizable length
- TOTP (Time-based One-Time Password) generation
- Data hashing with multiple algorithms (SHA-256, SHA-512, MD5)
- HMAC generation and verification
- Constant-time string comparison for security
- Cryptographically secure random value generation

### UploaderFactory
- Multer-based file upload handling with security validation
- Multiple file upload support with field mapping
- File type validation using MIME types and extensions
- Filename security validation and sanitization
- File size limits and upload count restrictions
- Secure filename generation option
- File content validation based on magic numbers
- Dangerous file extension filtering
- Automatic file cleanup on validation failure
- Custom error response handling
- Upload destination mapping per field

## Installation

```bash
npm install @reldens/server-utils
```

## Quick Start

### Basic Server Setup

```javascript
const { AppServerFactory } = require('@reldens/server-utils');

let appServerFactory = new AppServerFactory();
let serverResult = appServerFactory.createAppServer({
    port: 3000,
    useHttps: false,
    autoListen: true
});

if(serverResult){
    let { app, appServer } = serverResult;
    console.log('Server running on port 3000');
}
```

### File Operations

```javascript
const { FileHandler } = require('@reldens/server-utils');

// Read a JSON configuration file
let config = FileHandler.fetchFileJson('/path/to/config.json');
if(config){
    console.log('Configuration loaded:', config);
}

// Create a folder securely
if(FileHandler.createFolder('/path/to/new/folder')){
    console.log('Folder created successfully');
}

// Generate a secure filename
let secureFilename = FileHandler.generateSecureFilename('user-upload.jpg');
console.log('Secure filename:', secureFilename);
```

### Password Encryption

```javascript
const { Encryptor } = require('@reldens/server-utils');

// Hash a password
let hashedPassword = Encryptor.encryptPassword('userPassword123');
if(hashedPassword){
    console.log('Password hashed:', hashedPassword);
}

// Validate password
let isValid = Encryptor.validatePassword('userPassword123', hashedPassword);
console.log('Password valid:', isValid);

// Generate secure token
let secureToken = Encryptor.generateSecureToken(32);
console.log('Secure token:', secureToken);
```

### File Upload Configuration

```javascript
const { UploaderFactory } = require('@reldens/server-utils');

let uploaderFactory = new UploaderFactory({
    maxFileSize: 10 * 1024 * 1024, // 10MB
    mimeTypes: {
        image: ['image/jpeg', 'image/png', 'image/gif'],
        document: ['application/pdf', 'text/plain']
    },
    allowedExtensions: {
        image: ['.jpg', '.jpeg', '.png', '.gif'],
        document: ['.pdf', '.txt']
    },
    applySecureFileNames: true
});

let uploader = uploaderFactory.createUploader(
    [{ name: 'avatar' }, { name: 'document' }],
    { avatar: '/uploads/avatars', document: '/uploads/docs' },
    { avatar: 'image', document: 'document' }
);

// Use with Express
app.post('/upload', uploader, (req, res) => {
    console.log('Files uploaded:', req.files);
    res.json({ success: true });
});
```

## Advanced Configuration

### HTTPS Server with Multiple Domains

```javascript
let appServerFactory = new AppServerFactory();

appServerFactory.addDomain({
    hostname: 'example.com',
    keyPath: '/ssl/example.com.key',
    certPath: '/ssl/example.com.crt',
    aliases: ['www.example.com']
});

appServerFactory.addDomain({
    hostname: 'api.example.com',
    keyPath: '/ssl/api.example.com.key',
    certPath: '/ssl/api.example.com.crt'
});

let serverResult = appServerFactory.createAppServer({
    useHttps: true,
    useVirtualHosts: true,
    keyPath: '/ssl/default.key',
    certPath: '/ssl/default.crt',
    port: 443
});
```

### Development Mode Configuration

```javascript
let appServerFactory = new AppServerFactory();

// Add development domains
appServerFactory.addDevelopmentDomain('localhost');
appServerFactory.addDevelopmentDomain('dev.myapp.local');

let serverResult = appServerFactory.createAppServer({
    port: 3000,
    corsOrigin: ['http://localhost:3000', 'http://dev.myapp.local:3000'],
    developmentMultiplier: 5, // More lenient rate limiting in dev
});
```

### Custom Security Configuration

```javascript
let appServerFactory = new AppServerFactory();

let serverResult = appServerFactory.createAppServer({
    useHelmet: true,
    helmetConfig: {
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"]
            }
        }
    },
    globalRateLimit: 100, // requests per window
    windowMs: 60000, // 1 minute
    maxRequests: 30,
    trustedProxy: '127.0.0.1'
});
```

## API Reference

### AppServerFactory Methods

- `createAppServer(config)` - Creates and configures Express server
- `addDomain(domainConfig)` - Adds domain configuration for virtual hosting
- `addDevelopmentDomain(domain)` - Adds development domain pattern
- `setDomainMapping(mapping)` - Sets domain to configuration mapping
- `enableServeHome(app, callback)` - Enables homepage serving
- `serveStatics(app, staticPath)` - Serves static files
- `serveStaticsPath(app, route, staticPath)` - Serves static files on specific route
- `validateInput(input, type)` - Validates input against predefined patterns
- `enableCSP(cspOptions)` - Enables Content Security Policy
- `listen(port)` - Starts server listening
- `close()` - Gracefully closes server

### FileHandler Methods

- `exists(path)` - Checks if file or folder exists
- `createFolder(path)` - Creates folder with recursive option
- `remove(path)` - Removes file or folder recursively
- `copyFile(source, destination)` - Copies file to destination
- `copyFolderSync(source, destination)` - Copies folder recursively
- `readFile(path)` - Reads file contents as string
- `writeFile(path, content)` - Writes content to file
- `fetchFileJson(path)` - Reads and parses JSON file
- `fetchFileContents(path)` - Reads file with validation
- `updateFileContents(path, content)` - Updates existing file
- `isFile(path)` - Checks if path is file
- `isFolder(path)` - Checks if path is folder
- `getFilesInFolder(path, extensions)` - Lists files with optional filtering
- `validateFileType(path, type, allowedTypes, maxSize)` - Validates file type and size
- `detectFileType(path)` - Detects MIME type from file signature
- `generateSecureFilename(originalName)` - Generates cryptographically secure filename
- `quarantineFile(path, reason)` - Moves file to quarantine folder
- `createTempFile(prefix, extension)` - Creates temporary file path

### Encryptor Methods

- `encryptPassword(password)` - Hashes password with salt
- `validatePassword(password, hash)` - Validates password against hash
- `generateSecretKey()` - Generates 256-bit secret key
- `encryptData(data, key)` - Encrypts data with AES-256-GCM
- `decryptData(encryptedData, key)` - Decrypts AES-256-GCM data
- `generateSecureToken(length)` - Generates base64url token
- `generateTOTP(secret, timeStep)` - Generates time-based OTP
- `hashData(data, algorithm)` - Hashes data with specified algorithm
- `generateHMAC(data, secret, algorithm)` - Generates HMAC signature
- `verifyHMAC(data, secret, signature, algorithm)` - Verifies HMAC signature
- `constantTimeCompare(a, b)` - Performs constant-time string comparison

### UploaderFactory Methods

- `createUploader(fields, buckets, allowedTypes)` - Creates multer upload middleware
- `validateFilenameSecurity(filename)` - Validates filename for security
- `validateFile(file, allowedType, callback)` - Validates file during upload
- `validateFileContents(file, allowedType)` - Validates file content after upload
- `cleanupFiles(files)` - Removes uploaded files on error

## Security Features

### Path Traversal Protection
All file operations include comprehensive path validation to prevent directory traversal attacks and access to system files.

### Secure File Upload
File uploads are validated at multiple levels including filename, MIME type, file extension, file size, and content validation using magic number detection.

### Rate Limiting
Configurable rate limiting with development mode detection for appropriate thresholds in different environments.

### HTTPS Support
Full SSL/TLS support with SNI for multi-domain hosting and automatic certificate management.

### Input Validation
Built-in validators for common input types including email, username, strong passwords, alphanumeric strings, and IP addresses.

### Cryptographic Security
Industry-standard encryption using PBKDF2 for passwords, AES-256-GCM for data encryption, and secure random generation for tokens.

## Error Handling

All methods include comprehensive error handling with detailed error objects containing context information. Errors are logged appropriately and never expose sensitive system information.

---

## Documentation

[https://www.reldens.com/documentation/utils/](https://www.reldens.com/documentation/utils/)

Need something specific?

[Request a feature here: https://www.reldens.com/features-request](https://www.reldens.com/features-request)

---

### [Reldens](https://github.com/damian-pastorini/reldens/ "Reldens")

##### [By DwDeveloper](https://www.dwdeveloper.com/ "DwDeveloper")
