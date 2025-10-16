/**
 *
 * Reldens - Http2CdnServer
 *
 */

const http2 = require('http2');
const path = require('path');
const { FileHandler } = require('./file-handler');
const { ServerDefaultConfigurations } = require('./server-default-configurations');
const { ServerFactoryUtils } = require('./server-factory-utils');
const { ServerHeaders } = require('./server-headers');

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
        this.setupStreamHandler();
        return true;
    }

    setupStreamHandler()
    {
        this.http2Server.on('stream', (stream, headers) => {
            this.handleStream(stream, headers);
        });
    }

    handleStream(stream, headers)
    {
        let requestPath = headers[':path'];
        if(!requestPath){
            stream.respond({':status': 400});
            stream.end();
            return;
        }
        let requestOrigin = headers['origin'] || '';
        let allowedOrigin = ServerFactoryUtils.validateOrigin(requestOrigin, this.corsOrigins, this.corsAllowAll);
        if('OPTIONS' === headers[':method']){
            let optionsHeaders = {':status': 200};
            if(allowedOrigin){
                optionsHeaders['access-control-allow-origin'] = allowedOrigin;
            }
            optionsHeaders['access-control-allow-methods'] = this.corsMethods;
            optionsHeaders['access-control-allow-headers'] = this.corsHeaders;
            stream.respond(optionsHeaders);
            stream.end();
            return;
        }
        let filePath = this.resolveFilePath(requestPath);
        if(!filePath){
            stream.respond({':status': 404});
            stream.end();
            return;
        }
        let ext = path.extname(filePath);
        let cacheAge = ServerFactoryUtils.getCacheConfigForPath(filePath, this.cacheConfig);
        let responseHeaders = {':status': 200};
        let securityKeys = Object.keys(this.securityHeaders);
        for(let headerKey of securityKeys){
            responseHeaders[headerKey] = this.securityHeaders[headerKey];
        }
        if(allowedOrigin){
            responseHeaders['access-control-allow-origin'] = allowedOrigin;
        }
        if(this.varyHeader){
            responseHeaders['vary'] = this.varyHeader;
        }
        if(cacheAge){
            responseHeaders['cache-control'] = 'public, max-age='+cacheAge+', immutable';
        }
        if(this.mimeTypes[ext]){
            responseHeaders['content-type'] = this.mimeTypes[ext];
        }
        stream.respondWithFile(filePath, responseHeaders);
    }

    resolveFilePath(requestPath)
    {
        let cleanPath = ServerFactoryUtils.stripQueryString(requestPath);
        for(let staticPath of this.staticPaths){
            let fullPath = path.join(staticPath, cleanPath);
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
