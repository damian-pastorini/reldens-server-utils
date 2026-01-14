/**
 *
 * Reldens - Http2CdnServer
 *
 */

const http2 = require('http2');
const { FileHandler } = require('./file-handler');
const { ServerDefaultConfigurations } = require('./server-default-configurations');
const { ServerFactoryUtils } = require('./server-factory-utils');
const { ServerHeaders } = require('./server-headers');
const { ServerErrorHandler } = require('./server-error-handler');
const { EventDispatcher } = require('./event-dispatcher');
const { CdnRequestHandler } = require('./cdn-request-handler');

class Http2CdnServer
{

    constructor()
    {
        this.enabled = false;
        this.port = 8443;
        this.keyPath = '';
        this.certPath = '';
        this.httpsChain = '';
        this.staticPaths = [];
        this.cacheConfig = ServerDefaultConfigurations.cacheConfig;
        this.allowHTTP1 = true;
        this.http2Server = false;
        this.error = {};
        this.mimeTypes = ServerDefaultConfigurations.mimeTypes;
        this.corsOrigins = [];
        this.corsAllowAll = false;
        this.serverHeaders = new ServerHeaders();
        this.corsMethods = this.serverHeaders.http2CorsMethods;
        this.corsHeaders = this.serverHeaders.http2CorsHeaders;
        this.securityHeaders = this.serverHeaders.http2SecurityHeaders;
        this.varyHeader = this.serverHeaders.http2VaryHeader;
        this.onError = null;
        this.onRequestSuccess = null;
        this.onRequestError = null;
        this.onEvent = null;
        this.requestHandler = new CdnRequestHandler(this);
    }

    create()
    {
        if(!this.keyPath || !this.certPath){
            this.error = {message: 'Missing SSL certificates'};
            return false;
        }
        let key = FileHandler.readFile(this.keyPath);
        if(!key){
            this.error = {message: 'Could not read key from: '+this.keyPath};
            return false;
        }
        let cert = FileHandler.readFile(this.certPath);
        if(!cert){
            this.error = {message: 'Could not read cert from: '+this.certPath};
            return false;
        }
        let options = {key, cert, allowHTTP1: this.allowHTTP1};
        if(this.httpsChain){
            let ca = FileHandler.readFile(this.httpsChain);
            if(ca){
                options.ca = ca;
            }
        }
        this.http2Server = http2.createSecureServer(options);
        this.setupEventHandlers();
        EventDispatcher.dispatch(
            this.onEvent,
            'cdn-server-created',
            'http2CdnServer',
            this,
            {port: this.port, allowHTTP1: this.allowHTTP1}
        );
        return true;
    }

    setupEventHandlers()
    {
        this.http2Server.on('stream', (stream, headers) => {
            this.handleStream(stream, headers);
        });
        this.http2Server.on('request', (req, res) => {
            this.handleHttp1Request(req, res);
        });
        this.http2Server.on('error', (err) => {
            ServerErrorHandler.handleError(
                this.onError,
                'http2CdnServer',
                this,
                'server-error',
                err,
                {port: this.port}
            );
        });
        this.http2Server.on('tlsClientError', (err, tlsSocket) => {
            ServerErrorHandler.handleError(
                this.onError,
                'http2CdnServer',
                this,
                'tls-client-error',
                err,
                {port: this.port, remoteAddress: tlsSocket.remoteAddress}
            );
        });
        this.http2Server.on('sessionError', (err) => {
            ServerErrorHandler.handleError(
                this.onError,
                'http2CdnServer',
                this,
                'session-error',
                err,
                {port: this.port}
            );
        });
        EventDispatcher.dispatch(
            this.onEvent,
            'cdn-handlers-setup',
            'http2CdnServer',
            this,
            {port: this.port}
        );
    }

    invokeRequestSuccess(requestData)
    {
        if('function' !== typeof this.onRequestSuccess){
            return;
        }
        this.onRequestSuccess(requestData);
    }

    invokeRequestError(errorData)
    {
        if('function' !== typeof this.onRequestError){
            return;
        }
        this.onRequestError(errorData);
    }

    handleStream(stream, headers)
    {
        let requestContext = {
            isHttp2: true,
            method: headers[':method'],
            path: headers[':path'],
            hostname: headers['x-forwarded-host'] || headers[':authority'],
            origin: headers['origin'] || '',
            ip: null,
            userAgent: null,
            sendResponse: (statusCode, responseHeaders) => {
                if(responseHeaders){
                    stream.respond(responseHeaders);
                    stream.end();
                    return;
                }
                stream.respond({':status': statusCode});
                stream.end();
            },
            sendFile: (filePath, responseHeaders) => {
                stream.on('error', (err) => {
                    requestContext.errorCallback(err);
                });
                stream.on('finish', () => {
                    requestContext.successCallback();
                });
                stream.respondWithFile(filePath, responseHeaders);
            },
            onSuccess: (callback) => {
                requestContext.successCallback = callback;
            },
            onError: (callback) => {
                requestContext.errorCallback = callback;
            }
        };
        this.requestHandler.handleRequest(requestContext);
    }

    handleHttp1Request(req, res)
    {
        let requestContext = {
            isHttp2: false,
            method: req.method,
            path: req.url,
            hostname: req.headers['x-forwarded-host'] || req.headers.host,
            origin: req.headers['origin'] || '',
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            userAgent: req.headers['user-agent'],
            sendResponse: (statusCode, responseHeaders) => {
                if(responseHeaders){
                    res.writeHead(statusCode, responseHeaders);
                    res.end();
                    return;
                }
                res.writeHead(statusCode);
                res.end();
            },
            sendFile: (filePath, responseHeaders) => {
                let fileStream = FileHandler.createReadStream(filePath);
                fileStream.on('error', (err) => {
                    if(!res.headersSent){
                        res.writeHead(500);
                        res.end();
                    }
                    requestContext.errorCallback(err);
                });
                res.writeHead(200, responseHeaders);
                fileStream.pipe(res);
                res.on('finish', () => {
                    requestContext.successCallback();
                });
            },
            onSuccess: (callback) => {
                requestContext.successCallback = callback;
            },
            onError: (callback) => {
                requestContext.errorCallback = callback;
            }
        };
        this.requestHandler.handleRequest(requestContext);
    }

    resolveFilePath(requestPath)
    {
        let cleanPath = ServerFactoryUtils.stripQueryString(requestPath);
        for(let staticPath of this.staticPaths){
            let fullPath = FileHandler.joinPaths(staticPath, cleanPath);
            if(!FileHandler.exists(fullPath)){
                continue;
            }
            if(!FileHandler.isFile(fullPath)){
                continue;
            }
            return fullPath;
        }
        return false;
    }

    listen()
    {
        if(!this.http2Server){
            this.error = {message: 'HTTP2 server not created'};
            return false;
        }
        this.http2Server.listen(this.port);
        EventDispatcher.dispatch(
            this.onEvent,
            'cdn-server-listening',
            'http2CdnServer',
            this,
            {port: this.port}
        );
        return true;
    }

    async close()
    {
        if(!this.http2Server){
            return true;
        }
        return new Promise((resolve) => {
            this.http2Server.close(() => resolve(true));
        });
    }

}

module.exports.Http2CdnServer = Http2CdnServer;
