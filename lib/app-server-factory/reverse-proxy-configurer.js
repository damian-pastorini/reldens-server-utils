/**
 *
 * Reldens - ReverseProxyConfigurer
 *
 */

const { createProxyMiddleware } = require('http-proxy-middleware');
const { ServerHeaders } = require('../server-headers');
const { ServerErrorHandler } = require('../server-error-handler');
const { EventDispatcher } = require('../event-dispatcher');

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
        this.onError = null;
        this.onEvent = null;
    }

    setup(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.useVirtualHosts = config.useVirtualHosts || false;
        this.reverseProxyRules = config.reverseProxyRules || [];
        this.reverseProxyOptions = config.reverseProxyOptions || this.reverseProxyOptions;
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
            if(this.useVirtualHosts){
                app.use(pathPrefix, (req, res, next) => {
                    let hostname = this.extractHostname(req);
                    if(hostname !== rule.hostname){
                        return next();
                    }
                    return proxyMiddleware(req, res, next);
                });
                continue;
            }
            app.use(pathPrefix, proxyMiddleware);
        }
    }

    extractHostname(req)
    {
        if(req.domain && req.domain.hostname){
            return req.domain.hostname;
        }
        let host = req.get('host') || '';
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
        if('boolean' === typeof rule.websocket){
            options.ws = rule.websocket;
        }
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
            proxyReq: (proxyReq, req) => {
                if(req.headers['x-forwarded-for']){
                    return;
                }
                let clientIp = req.ip || req.connection.remoteAddress || '';
                proxyReq.setHeader(this.serverHeaders.proxyForwardedFor, clientIp);
                proxyReq.setHeader(this.serverHeaders.proxyForwardedProto, req.protocol);
                proxyReq.setHeader(this.serverHeaders.proxyForwardedHost, req.get('host') || '');
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
