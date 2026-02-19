/**
 *
 * Reldens - CdnRequestHandler
 *
 */

const { FileHandler } = require('./file-handler');
const { ServerFactoryUtils } = require('./server-factory-utils');

class CdnRequestHandler
{

    constructor(cdnServer)
    {
        this.cdnServer = cdnServer;
    }

    handleRequest(requestContext)
    {
        let startTime = Date.now();
        let requestData = {
            serverType: 'cdn',
            method: requestContext.method,
            path: requestContext.path,
            hostname: requestContext.hostname,
            statusCode: 200,
            responseTime: 0,
            ip: requestContext.ip,
            userAgent: requestContext.userAgent,
            timestamp: new Date().toISOString()
        };
        try {
            if(!requestData.path){
                requestContext.sendResponse(400);
                return;
            }
            let requestOrigin = requestContext.origin || '';
            let allowedOrigin = ServerFactoryUtils.validateOrigin(
                requestOrigin,
                this.cdnServer.corsOrigins,
                this.cdnServer.corsAllowAll
            );
            if('OPTIONS' === requestData.method){
                this.handleOptionsRequest(requestContext, allowedOrigin);
                return;
            }
            let filePath = this.cdnServer.resolveFilePath(requestData.path);
            if(!filePath){
                requestData.statusCode = 404;
                requestData.responseTime = Date.now()-startTime;
                requestContext.sendResponse(404);
                this.cdnServer.invokeRequestError(requestData);
                return;
            }
            let responseHeaders = this.buildResponseHeaders(allowedOrigin, filePath, requestContext.isHttp2);
            requestContext.onSuccess(() => {
                requestData.responseTime = Date.now()-startTime;
                this.cdnServer.invokeRequestSuccess(requestData);
            });
            requestContext.onError((err) => {
                requestData.statusCode = 500;
                requestData.responseTime = Date.now()-startTime;
                requestData.error = err;
                this.cdnServer.handleError(
                    requestContext.isHttp2 ? 'stream-error' : 'http1-stream-error',
                    err,
                    {port: this.cdnServer.port, path: requestData.path}
                );
                this.cdnServer.invokeRequestError(requestData);
            });
            requestContext.sendFile(filePath, responseHeaders);
        } catch (err) {
            requestData.statusCode = 500;
            requestData.responseTime = Date.now()-startTime;
            requestData.error = err;
            this.cdnServer.handleError(
                requestContext.isHttp2 ? 'handle-stream-error' : 'handle-http1-request-error',
                err,
                {port: this.cdnServer.port, path: requestData.path}
            );
            this.cdnServer.invokeRequestError(requestData);
            requestContext.sendResponse(500);
        }
    }

    handleOptionsRequest(requestContext, allowedOrigin)
    {
        let optionsHeaders = requestContext.isHttp2 ? {':status': 200} : {};
        if(allowedOrigin){
            optionsHeaders['access-control-allow-origin'] = allowedOrigin;
        }
        optionsHeaders['access-control-allow-methods'] = this.cdnServer.corsMethods;
        optionsHeaders['access-control-allow-headers'] = this.cdnServer.corsHeaders;
        requestContext.sendResponse(200, optionsHeaders);
    }

    buildResponseHeaders(allowedOrigin, filePath, isHttp2)
    {
        let ext = FileHandler.extension(filePath);
        let cacheAge = ServerFactoryUtils.getCacheConfigForPath(filePath, this.cdnServer.cacheConfig);
        let responseHeaders = isHttp2 ? {':status': 200} : {};
        let securityKeys = Object.keys(this.cdnServer.securityHeaders);
        for(let headerKey of securityKeys){
            responseHeaders[headerKey] = this.cdnServer.securityHeaders[headerKey];
        }
        if(allowedOrigin){
            responseHeaders['access-control-allow-origin'] = allowedOrigin;
        }
        if(this.cdnServer.varyHeader){
            responseHeaders['vary'] = this.cdnServer.varyHeader;
        }
        if(cacheAge){
            responseHeaders['cache-control'] = 'public, max-age='+cacheAge+', immutable';
        }
        if(this.cdnServer.mimeTypes[ext]){
            responseHeaders['content-type'] = this.cdnServer.mimeTypes[ext];
        }
        return responseHeaders;
    }

}

module.exports.CdnRequestHandler = CdnRequestHandler;
