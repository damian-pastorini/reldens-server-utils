/**
 *
 * Reldens - Http2CdnServer
 *
 */

const http2 = require('http2');
const tls = require('tls');
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
        this.domains = [];
        this.useMultiCert = false;
        this.defaultDomain = null;
        this.sniContexts = {};
        this.eventSource = 'http2CdnServer';
    }

    dispatch(eventName, eventData)
    {
        EventDispatcher.dispatch(this.onEvent, eventName, this.eventSource, this, eventData);
    }

    handleError(errorType, error, context)
    {
        ServerErrorHandler.handleError(this.onError, this.eventSource, this, errorType, error, context);
    }

    create()
    {
        this.setupDomainConfiguration();
        if(!this.validateCertificates()){
            return false;
        }
        if(this.useMultiCert){
            this.buildSniContexts();
        }
        let options = this.buildServerOptions();
        if(!options){
            return false;
        }
        this.http2Server = http2.createSecureServer(options);
        this.setupEventHandlers();
        this.dispatch(
            'cdn-server-created',
            {port: this.port, allowHTTP1: this.allowHTTP1, multiCert: this.useMultiCert})
        ;
        return true;
    }

    setupDomainConfiguration()
    {
        if(this.domains && 0 < this.domains.length){
            this.useMultiCert = true;
            this.defaultDomain = this.domains[0];
            this.dispatch('cdn-multi-cert-enabled', {domains: this.domains.map(d => d.hostname)});
            return;
        }
        if(this.keyPath && this.certPath){
            this.useMultiCert = false;
            this.domains = [{hostname: 'default', keyPath: this.keyPath, certPath: this.certPath}];
            this.defaultDomain = this.domains[0];
            this.dispatch('cdn-single-cert-mode', {hostname: this.defaultDomain.hostname});
            return;
        }
        this.error = {message: 'HTTP/2 CDN requires domains array or keyPath/certPath'};
    }

    validateCertificates()
    {
        for(let domain of this.domains){
            if(!FileHandler.exists(domain.keyPath)){
                this.error = {message: 'Certificate key not found for '+domain.hostname+': '+domain.keyPath};
                this.handleError('certificate-key-not-found', this.error, {hostname: domain.hostname, keyPath: domain.keyPath});
                return false;
            }
            if(!FileHandler.exists(domain.certPath)){
                this.error = {message: 'Certificate file not found for '+domain.hostname+': '+domain.certPath};
                this.handleError('certificate-not-found', this.error, {hostname: domain.hostname, certPath: domain.certPath});
                return false;
            }
        }
        return true;
    }

    buildSniContexts()
    {
        for(let domain of this.domains){
            let key = FileHandler.readFile(domain.keyPath);
            let cert = FileHandler.readFile(domain.certPath);
            this.sniContexts[domain.hostname] = tls.createSecureContext({key, cert});
        }
    }

    getSniCallback()
    {
        return (servername, callback) => {
            this.dispatch('cdn-sni-request', {servername});
            let context = this.sniContexts[servername];
            if(!context){
                this.dispatch('cdn-sni-fallback', {servername, defaultHostname: this.defaultDomain.hostname});
                context = this.sniContexts[this.defaultDomain.hostname];
            }
            callback(null, context);
        };
    }

    buildServerOptions()
    {
        let key = FileHandler.readFile(this.defaultDomain.keyPath);
        if(!key){
            this.error = {message: 'Could not read key from: '+this.defaultDomain.keyPath};
            return false;
        }
        let cert = FileHandler.readFile(this.defaultDomain.certPath);
        if(!cert){
            this.error = {message: 'Could not read cert from: '+this.defaultDomain.certPath};
            return false;
        }
        let options = {key, cert, allowHTTP1: this.allowHTTP1};
        if(this.httpsChain){
            let ca = FileHandler.readFile(this.httpsChain);
            if(ca){
                options.ca = ca;
            }
        }
        if(this.useMultiCert){
            options.SNICallback = this.getSniCallback();
        }
        return options;
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
            this.handleError('server-error', err, {port: this.port});
        });
        this.http2Server.on('tlsClientError', (err, tlsSocket) => {
            this.handleError('tls-client-error', err, {port: this.port, remoteAddress: tlsSocket.remoteAddress});
        });
        this.http2Server.on('sessionError', (err) => {
            this.handleError('session-error', err, {port: this.port});
        });
        this.dispatch('cdn-handlers-setup', {port: this.port});
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
        this.dispatch('cdn-server-listening', {port: this.port});
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
