/**
 *
 * Reldens - ReverseProxyConfigurer
 *
 */

const { createProxyMiddleware } = require('http-proxy-middleware');
const proxyaddr = require('proxy-addr');
const { ServerHeaders } = require('../server-headers');
const { ServerErrorHandler } = require('../server-error-handler');
const { EventDispatcher } = require('../event-dispatcher');
const { IpListsConfigurer } = require('./ip-lists-configurer');
const { RateLimitConfigurer } = require('./rate-limit-configurer');

class ReverseProxyConfigurer
{

    constructor()
    {
        this.isDevelopmentMode = false;
        this.useVirtualHosts = false;
        this.reverseProxyRules = [];
        this.reverseProxyOptions = {
            changeOrigin: true,
            ws: true,
            secure: false,
            logLevel: 'warn'
        };
        this.serverHeaders = new ServerHeaders();
        this.app = false;
        this.ipListsConfigurer = new IpListsConfigurer();
        this.rateLimitConfigurer = new RateLimitConfigurer();
        this.upgradeRules = [];
        this.notFoundUpgradeResponse = 'HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n';
        this.forbiddenUpgradeResponse = 'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n';
        this.tooManyRequestsUpgradeResponse = 'HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n';
        this.onError = null;
        this.onEvent = null;
    }

    setup(app, config)
    {
        this.app = app;
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.useVirtualHosts = config.useVirtualHosts || false;
        this.reverseProxyRules = config.reverseProxyRules || [];
        this.reverseProxyOptions = config.reverseProxyOptions || this.reverseProxyOptions;
        this.ipListsConfigurer = config.ipListsConfigurer || this.ipListsConfigurer;
        this.rateLimitConfigurer = config.rateLimitConfigurer || this.rateLimitConfigurer;
        this.upgradeRules = [];
        this.onError = config.onError || null;
        this.onEvent = config.onEvent || null;
        if(0 === this.reverseProxyRules.length){
            return;
        }
        this.applyRules(app);
        EventDispatcher.dispatch(
            this.onEvent,
            'reverse-proxy-configured',
            'reverseProxyConfigurer',
            this,
            {rulesCount: this.reverseProxyRules.length, useVirtualHosts: this.useVirtualHosts}
        );
    }

    applyRules(app)
    {
        for(let rule of this.reverseProxyRules){
            if(!this.validateProxyRule(rule)){
                continue;
            }
            let proxyMiddleware = this.createProxyMiddleware(rule);
            if(!proxyMiddleware){
                continue;
            }
            let pathPrefix = rule.pathPrefix || '/';
            if('boolean' === typeof rule.websocket ? rule.websocket : true === this.reverseProxyOptions.ws){
                this.upgradeRules.push({hostname: rule.hostname, pathPrefix, proxyMiddleware});
            }
            if(this.useVirtualHosts){
                app.use(pathPrefix, (req, res, next) => {
                    let hostname = this.extractHostname(req);
                    if(hostname !== rule.hostname){
                        return next();
                    }
                    return this.proxyRequest(proxyMiddleware, req, res, next);
                });
                continue;
            }
            app.use(pathPrefix, (req, res, next) => this.proxyRequest(proxyMiddleware, req, res, next));
        }
    }

    async proxyRequest(proxyMiddleware, req, res, next)
    {
        let clientAddress = String(proxyaddr(req, this.app.get('trust proxy fn')) || '');
        if(!await this.rateLimitConfigurer.isWithinGlobalLimit(clientAddress)){
            return res.status(429).send(this.rateLimitConfigurer.tooManyRequestsMessage);
        }
        this.applyForwardedHeaders(req);
        return proxyMiddleware(req, res, next);
    }

    resolveForwardedHeaders(req)
    {
        let trustProxyFunction = this.app.get('trust proxy fn');
        let isTrustedPeer = trustProxyFunction(req.socket.remoteAddress, 0);
        let forwardedHeaders = {
            [this.serverHeaders.proxyForwardedFor.toLowerCase()]: String(proxyaddr(req, trustProxyFunction) || ''),
            [this.serverHeaders.proxyForwardedProto.toLowerCase()]: this.resolveTrustedHeaderValue(
                req,
                this.serverHeaders.proxyForwardedProto,
                isTrustedPeer,
                req.socket.encrypted ? 'https' : 'http'
            ),
            [this.serverHeaders.proxyForwardedHost.toLowerCase()]: this.resolveTrustedHeaderValue(
                req,
                this.serverHeaders.proxyForwardedHost,
                isTrustedPeer,
                req.headers.host || ''
            )
        };
        forwardedHeaders[this.serverHeaders.proxyRealIp.toLowerCase()] = forwardedHeaders[
            this.serverHeaders.proxyForwardedFor.toLowerCase()
        ];
        return forwardedHeaders;
    }

    resolveTrustedHeaderValue(req, headerName, isTrustedPeer, fallbackValue)
    {
        let headerValue = String(req.headers[headerName.toLowerCase()] || '');
        if(!isTrustedPeer){
            return fallbackValue;
        }
        if('' === headerValue){
            return fallbackValue;
        }
        return headerValue.split(',').shift().trim();
    }

    applyForwardedHeaders(req)
    {
        let forwardedHeaders = this.resolveForwardedHeaders(req);
        delete req.headers[this.serverHeaders.proxyClientIp.toLowerCase()];
        Object.assign(req.headers, forwardedHeaders);
    }

    applyUpgradeForwardedHeaders(proxyReq, req)
    {
        let forwardedHeaders = this.resolveForwardedHeaders(req);
        proxyReq.removeHeader(this.serverHeaders.proxyClientIp);
        for(let headerName of Object.keys(forwardedHeaders)){
            proxyReq.setHeader(headerName, forwardedHeaders[headerName]);
        }
    }

    attachToServer(server)
    {
        if(0 === this.upgradeRules.length){
            return false;
        }
        server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head, server));
        return true;
    }

    async handleUpgrade(req, socket, head, server)
    {
        let upgradeRule = this.findUpgradeRule(req);
        if(!upgradeRule){
            if(1 < server.listenerCount('upgrade')){
                return false;
            }
            return socket.end(this.notFoundUpgradeResponse);
        }
        let clientAddress = String(proxyaddr(req, this.app.get('trust proxy fn')) || '');
        if(!this.ipListsConfigurer.isAllowed(clientAddress)){
            return socket.end(this.forbiddenUpgradeResponse);
        }
        if(!await this.rateLimitConfigurer.isWithinGlobalLimit(clientAddress)){
            return socket.end(this.tooManyRequestsUpgradeResponse);
        }
        return upgradeRule.proxyMiddleware.upgrade(req, socket, head);
    }

    findUpgradeRule(req)
    {
        let hostname = this.extractHostname(req);
        let requestPath = String(req.url || '').split('?').shift();
        for(let upgradeRule of this.upgradeRules){
            if(this.useVirtualHosts && hostname !== upgradeRule.hostname){
                continue;
            }
            if(this.matchesPathPrefix(requestPath, upgradeRule.pathPrefix)){
                return upgradeRule;
            }
        }
        return false;
    }

    matchesPathPrefix(requestPath, pathPrefix)
    {
        let mountPath = pathPrefix.replace(/\/+$/, '');
        if('' === mountPath){
            return true;
        }
        if(requestPath === mountPath){
            return true;
        }
        return 0 === requestPath.indexOf(mountPath+'/');
    }

    extractHostname(req)
    {
        if(req.domain && req.domain.hostname){
            return req.domain.hostname;
        }
        let host = req.headers.host || '';
        return host.split(':')[0].toLowerCase();
    }

    validateProxyRule(rule)
    {
        if(!rule){
            return false;
        }
        if(!rule.hostname){
            return false;
        }
        if(!rule.target){
            return false;
        }
        return true;
    }

    createProxyMiddleware(rule)
    {
        let options = Object.assign({}, this.reverseProxyOptions);
        if('boolean' === typeof rule.changeOrigin){
            options.changeOrigin = rule.changeOrigin;
        }
        options.ws = false;
        if('boolean' === typeof rule.secure){
            options.secure = rule.secure;
        }
        if('string' === typeof rule.logLevel){
            options.logLevel = rule.logLevel;
        }
        options.target = rule.target;
        options.on = {
            error: (error, req, res) => {
                this.handleProxyError(error, req, res);
            },
            proxyReqWs: (proxyReq, req) => {
                this.applyUpgradeForwardedHeaders(proxyReq, req);
            }
        };
        return createProxyMiddleware(options);
    }

    handleProxyError(error, req, res)
    {
        let hostname = req.headers.host || 'unknown';
        let requestPath = req.path || req.url || 'unknown';
        ServerErrorHandler.handleError(
            this.onError,
            'reverseProxyConfigurer',
            this,
            'proxy-error',
            error,
            {request: req, response: res, hostname: hostname, path: requestPath}
        );
        if('function' !== typeof res.status){
            return res.destroy();
        }
        if(res.headersSent){
            return;
        }
        if('ECONNREFUSED' === error.code){
            return res.status(502).send('Bad Gateway - Backend server unavailable');
        }
        if('ETIMEDOUT' === error.code || 'ESOCKETTIMEDOUT' === error.code){
            return res.status(504).send('Gateway Timeout');
        }
        return res.status(500).send('Proxy Error');
    }

}

module.exports.ReverseProxyConfigurer = ReverseProxyConfigurer;
