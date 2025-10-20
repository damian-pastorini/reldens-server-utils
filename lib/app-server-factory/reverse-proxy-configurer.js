/**
 *
 * Reldens - ReverseProxyConfigurer
 *
 */

const { createProxyMiddleware } = require('http-proxy-middleware');
const { ServerHeaders } = require('../server-headers');

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
    }

    setup(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.useVirtualHosts = config.useVirtualHosts || false;
        this.reverseProxyRules = config.reverseProxyRules || [];
        this.reverseProxyOptions = config.reverseProxyOptions || this.reverseProxyOptions;
        if(0 === this.reverseProxyRules.length){
            return;
        }
        this.applyRules(app);
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
        options.onError = this.handleProxyError.bind(this);
        options.onProxyReq = (proxyReq, req) => {
            if(req.headers['x-forwarded-for']){
                return;
            }
            let clientIp = req.ip || req.connection.remoteAddress || '';
            proxyReq.setHeader(this.serverHeaders.proxyForwardedFor, clientIp);
            proxyReq.setHeader(this.serverHeaders.proxyForwardedProto, req.protocol);
            proxyReq.setHeader(this.serverHeaders.proxyForwardedHost, req.get('host') || '');
        };
        return createProxyMiddleware(options);
    }

    handleProxyError(err, req, res)
    {
        if(res.headersSent){
            return;
        }
        if('ECONNREFUSED' === err.code){
            return res.status(502).send('Bad Gateway - Backend server unavailable');
        }
        if('ETIMEDOUT' === err.code || 'ESOCKETTIMEDOUT' === err.code){
            return res.status(504).send('Gateway Timeout');
        }
        return res.status(500).send('Proxy Error');
    }

}

module.exports.ReverseProxyConfigurer = ReverseProxyConfigurer;
