# Package Architecture

## Design Philosophy

**@reldens/server-utils** is an independent utility package that provides server infrastructure without coupling to other Reldens packages (like @reldens/utils).

## Core Principles

### 1. Independence
- No dependencies on @reldens/utils or other Reldens packages
- Self-contained utility classes
- Can be used standalone or integrated into Reldens

### 2. Callback-Based Extensibility
The package provides **hooks via callbacks** instead of direct implementations.

**Pattern:**
- Package provides callback properties
- Package calls these callbacks at specific points
- Application provides callback implementations
- Application wires callbacks to their own logging/monitoring systems

### 3. Separation of Concerns
- **reldens-server-utils**: Provides server infrastructure and callback hooks
- **Application**: Provides implementations (logging, monitoring, error handling)
- **@reldens/utils**: Provides shared utilities (Logger, Shortcuts, etc.)

The package does NOT import Logger. Applications import Logger and wire it to package callbacks.

## Available Callbacks

### onError
Custom error handler for server errors.

**Called by:** ServerErrorHandler static class

**Data structure:**
- `instanceName` - Which server component had the error
- `instance` - The component instance
- `key` - Error type identifier
- `error` - The error object
- `context` - Additional contextual data

**Error points:**
- Virtual host resolution errors
- SNI certificate loading errors
- Server creation errors
- Stream errors
- TLS client errors
- Session errors
- HTTP/1 fallback errors
- Reverse proxy errors

**Example:**
```javascript
let config = {
    onError: (errorData) => {
        Logger.error('Server error:', errorData.key, errorData.error.message);
    }
};
```

### onRequestSuccess
Called for successful HTTP requests (status code < 400).

**Called by:** RequestLogger middleware

**Data structure:**
- `method` - HTTP method (GET, POST, etc.)
- `path` - Request path
- `statusCode` - HTTP status code
- `responseTime` - Response time in milliseconds
- `ip` - Client IP address
- `userAgent` - Client user agent
- `timestamp` - ISO timestamp

**Example:**
```javascript
let config = {
    onRequestSuccess: (requestData) => {
        Logger.info('Request:', requestData.method, requestData.path, requestData.statusCode, requestData.responseTime+'ms');
    }
};
```

### onRequestError
Called for failed HTTP requests (status code >= 400).

**Called by:** RequestLogger middleware

**Data structure:**
- `method` - HTTP method
- `path` - Request path
- `statusCode` - HTTP status code
- `responseTime` - Response time in milliseconds
- `ip` - Client IP address
- `userAgent` - Client user agent
- `timestamp` - ISO timestamp

**Example:**
```javascript
let config = {
    onRequestError: (errorData) => {
        Logger.error('Request error:', errorData.method, errorData.path, errorData.statusCode);
    }
};
```

### onEvent
Generic lifecycle event callback for server initialization and configuration events.

**Called by:** EventDispatcher static class

**Data structure:**
- `eventType` - Event type identifier
- `instanceName` - Which component dispatched the event
- `instance` - The component instance
- `data` - Event-specific data
- `timestamp` - ISO timestamp

**Event types:**
- `app-server-created` - Express app server created
- `http2-cdn-created` - HTTP/2 CDN server created
- `app-server-listening` - Server started listening
- `http-server-created` - HTTP server created
- `https-server-created` - HTTPS server created
- `sni-server-created` - SNI server created
- `domain-added` - Virtual host domain added
- `protocol-enforcement-enabled` - Protocol enforcement configured
- `helmet-configured` - Helmet security configured
- `xss-protection-enabled` - XSS protection configured
- `cors-configured` - CORS configured
- `rate-limiting-configured` - Rate limiting configured
- `reverse-proxy-configured` - Reverse proxy configured
- `development-mode-detected` - Development mode detected
- `cdn-server-created` - CDN server instance created
- `cdn-handlers-setup` - CDN event handlers configured
- `cdn-server-listening` - CDN server started listening

**Example:**
```javascript
let config = {
    onEvent: (eventData) => {
        Logger.debug('Event:', eventData.eventType, eventData.instanceName);
    }
};
```

## Integration Pattern

**Application Setup:**
```javascript
const { AppServerFactory } = require('@reldens/server-utils');
const { Logger } = require('@reldens/utils');

let factory = new AppServerFactory();

let config = {
    port: 8080,
    onError: (errorData) => {
        Logger.error('Server error:', errorData.key, errorData.error.message);
    },
    onRequestSuccess: (requestData) => {
        Logger.info('Request:', requestData.method, requestData.path, requestData.statusCode);
    },
    onRequestError: (errorData) => {
        Logger.error('Request error:', errorData.method, errorData.path, errorData.statusCode);
    },
    onEvent: (eventData) => {
        Logger.debug('Event:', eventData.eventType);
    }
};

let serverResult = factory.createAppServer(config);
```

This pattern keeps the utility package independent while allowing full integration with application-specific logging and monitoring systems.
