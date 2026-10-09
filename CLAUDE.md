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
# Run the unit tests (tests/run-tests.js runs every class listed in its testClasses)
npm test
```

## Architecture

See `.claude/package-architecture.md` for detailed information about:
- Design philosophy and independence principles
- Callback-based extensibility pattern
- Available callbacks (onError, onRequestSuccess, onRequestError, onEvent)
- Integration patterns

See `.claude/api-reference.md` for complete API documentation of all classes and methods.

## Core Classes Summary

**FileHandler** - Singleton wrapper for Node.js fs and path modules. Used instead of direct require('fs') or require('path') throughout Reldens.

**AppServerFactory** - Creates Express app servers with modular security components. Supports HTTP, HTTPS, HTTP/2, virtual hosts, CDN integration, reverse proxy, and callback-based logging.

**Encryptor** - Singleton for cryptographic operations including password hashing, data encryption, token generation, and HMAC verification.

**UploaderFactory** - File upload handling with Multer and multi-level security validation.

**Http2CdnServer** - HTTP/2 secure server for CDN-like static file serving with multi-certificate SNI support, CORS, cache headers, and callback-based logging.

## Utility Classes Summary

**PackageResolver** - Singleton that loads optional packages from the project `node_modules`, returns `false` and fills `error.message` (with the `npm install` command) when a package is missing; the caller logs it.

**RequestLogger** - Express middleware for request logging that invokes callbacks based on status codes.

**EventDispatcher** - Static utility for dispatching lifecycle events with structured event data.

**ServerErrorHandler** - Centralized error handling with structured error context.

**ServerDefaultConfigurations** - Static class providing MIME types and cache configurations.

**ServerFactoryUtils** - Static utility methods for cache config, CORS validation, and URL manipulation.

**ServerHeaders** - Centralized header management for HTTP/2, security, cache, and proxy headers.

**ExpressSession / ExpressBasicAuth** - The `express-session` and `express-basic-auth` modules exported from `index.js`, so Reldens requires them from this package instead of listing them in its own package.json.

## Security Configurers Summary

Located in `lib/app-server-factory/`:
- **DevelopmentModeDetector** - Auto-detect development environment
- **ProtocolEnforcer** - HTTP/HTTPS protocol enforcement
- **SecurityConfigurer** - Helmet integration and XSS protection
- **CorsConfigurer** - CORS with dynamic origin validation
- **RateLimitConfigurer** - Global and endpoint-specific rate limiting
- **ReverseProxyConfigurer** - Domain-based reverse proxy with WebSocket support
- **IpListsConfigurer** - Allow and deny address lists with validated CIDR entries
- **ClientAddressGuard** - Resolves the client address with the trusted proxy settings on the raw server upgrade and matchmake requests

## Important Notes

### FileHandler Usage
- **ALWAYS use FileHandler** instead of Node.js fs/path modules
- FileHandler methods have built-in error handling - no try/catch needed
- DO NOT enclose FileHandler methods in try/catch blocks
- DO NOT use FileHandler.exists to validate other FileHandler methods (e.g., before createFolder)

### Callback System
- Package provides callback hooks (onError, onRequestSuccess, onRequestError, onEvent)
- Applications provide implementations via configuration
- Package does NOT import @reldens/utils Logger
- Applications wire callbacks to their own logging/monitoring systems

### Server Configuration
- AppServerFactory handles all Express server configuration
- All server utilities support both HTTP and HTTPS
- Virtual hosts with SNI support for multiple domains
- HTTP/2 CDN server integration for static file serving
- Reverse proxy with WebSocket support

### Security
- Multi-level validation for file uploads
- XSS protection with request body sanitization
- CSP management with Helmet integration
- CORS with dynamic origin validation (supports strings and RegExp)
- Rate limiting with development mode awareness
- Client address resolved from the socket peer, the forwarding headers are only trusted through `trustedProxy`
- The reverse proxy always replaces the visitor forwarding headers (X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, X-Forwarded-Host, X-Client-IP) on requests and WebSocket upgrades before forwarding
- The reverse proxy handles the server upgrades itself: only the rule hostname and path prefix are proxied and the IP lists are applied, the http-proxy-middleware `ws` option stays off because it proxies every upgrade of the server
- The proxy middleware runs before the global rate limiter, so the proxied requests and upgrades are counted through `RateLimitConfigurer.isWithinGlobalLimit()` in the same store
- No class reads X-Forwarded-For, X-Forwarded-Host or X-Forwarded-Proto directly: Express code uses `req.ip`, `req.hostname` and `req.protocol`, raw requests use proxy-addr with the app `trust proxy` function (`ClientAddressGuard`, `ReverseProxyConfigurer`, `Http2CdnServer.resolveRequestOrigin`)
- This package is the security boundary of every Reldens server: never propose replacing, removing or reimplementing a component (for example the `http-proxy-middleware` reverse proxy) without first listing every attack the replacement takes over, and verify in the source whether an audit finding is reachable from our usage before proposing to replace a dependency
