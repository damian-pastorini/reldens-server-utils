/**
 *
 * Reldens - AppServerFactory
 *
 */

const { FileHandler } = require('./file-handler');
const http = require('http');
const https = require('https');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const helmet = require('helmet');
const xss = require('xss-clean');

class AppServerFactory
{

    constructor()
    {
        this.applicationFramework = express;
        this.bodyParser = bodyParser;
        this.session = session;
        this.appServer = false;
        this.app = express();
        this.rateLimit = rateLimit;
        this.useCors = 1 === Number(process.env.RELDENS_USE_CORS || 1);
        this.useExpressJson = 1 === Number(process.env.RELDENS_USE_EXPRESS_JSON || 1);
        this.useUrlencoded = 1 === Number(process.env.RELDENS_USE_URLENCODED || 1);
        this.encoding = String(process.env.RELDENS_DEFAULT_ENCODING || 'utf-8');
        this.useHttps = 1 === Number(process.env.RELDENS_EXPRESS_USE_HTTPS || 0);
        this.passphrase = String(process.env.RELDENS_EXPRESS_HTTPS_PASSPHRASE || '');
        this.httpsChain = String(process.env.RELDENS_EXPRESS_HTTPS_CHAIN || '');
        this.keyPath = String(process.env.RELDENS_EXPRESS_HTTPS_PRIVATE_KEY || '');
        this.certPath = String(process.env.RELDENS_EXPRESS_HTTPS_CERT || '');
        this.trustedProxy = String(process.env.RELDENS_EXPRESS_TRUSTED_PROXY || '');
        this.windowMs = Number(process.env.RELDENS_EXPRESS_RATE_LIMIT_MS || 60000);
        this.maxRequests = Number(process.env.RELDENS_EXPRESS_RATE_LIMIT_MAX_REQUESTS || 30);
        this.applyKeyGenerator = 1 === Number(process.env.RELDENS_EXPRESS_RATE_LIMIT_APPLY_KEY_GENERATOR || 0);
        this.jsonLimit = String(process.env.RELDENS_EXPRESS_JSON_LIMIT || '1mb');
        this.urlencodedLimit = String(process.env.RELDENS_EXPRESS_URLENCODED_LIMIT || '1mb');
        this.useHelmet = 1 === Number(process.env.RELDENS_USE_HELMET || 1);
        this.useXssProtection = 1 === Number(process.env.RELDENS_USE_XSS_PROTECTION || 1);
        this.globalRateLimit = 1 === Number(process.env.RELDENS_GLOBAL_RATE_LIMIT || 0);
        this.corsOrigin = String(process.env.RELDENS_CORS_ORIGIN || '*');
        this.corsMethods = String(process.env.RELDENS_CORS_METHODS || 'GET,POST').split(',');
        this.corsHeaders = String(process.env.RELDENS_CORS_HEADERS || 'Content-Type,Authorization').split(',');
        this.tooManyRequestsMessage = String(
            process.env.RELDENS_TOO_MANY_REQUESTS_MESSAGE || 'Too many requests, please try again later.'
        );
        this.error = {};
        this.processErrorResponse = false;
    }

    createAppServer(appServerConfig)
    {
        if(appServerConfig){
            Object.assign(this, appServerConfig);
        }
        if(this.useHelmet){
            this.app.use(helmet());
        }
        if(this.useCors){
            let corsOptions = {
                origin: this.corsOrigin,
                methods: this.corsMethods,
                allowedHeaders: this.corsHeaders
            };
            this.app.use(cors(corsOptions));
        }
        if(this.globalRateLimit){
            let limiterParams = {
                windowMs: this.windowMs,
                max: this.maxRequests,
                standardHeaders: true,
                legacyHeaders: false,
                message: this.tooManyRequestsMessage
            };
            if(this.applyKeyGenerator){
                limiterParams.keyGenerator = function(req){
                    return req.ip;
                };
            }
            this.app.use(this.rateLimit(limiterParams));
        }
        if(this.useXssProtection){
            this.app.use(xss());
        }
        if(this.useExpressJson){
            this.app.use(this.applicationFramework.json({
                limit: this.jsonLimit,
                verify: this.verifyContentTypeJson
            }));
        }
        if(this.useUrlencoded){
            this.app.use(this.bodyParser.urlencoded({
                extended: true,
                limit: this.urlencodedLimit
            }));
        }
        if('' !== this.trustedProxy){
            this.app.enable('trust proxy', this.trustedProxy);
        }
        this.appServer = this.createServer();
        return {app: this.app, appServer: this.appServer};
    }

    verifyContentTypeJson(req, res, buf)
    {
        let contentType = req.headers['content-type'] || '';
        if(
            req.method === 'POST'
            && 0 < buf.length
            && !contentType.includes('application/json')
            && !contentType.includes('multipart/form-data')
        ){
            throw new Error('Invalid content-type');
        }
    }

    createServer()
    {
        if(!this.useHttps){
            return http.createServer(this.app);
        }
        let key = FileHandler.readFile(this.keyPath, 'Key');
        if(!key){
            return false;
        }
        let cert = FileHandler.readFile(this.certPath, 'Cert');
        if(!cert){
            return false;
        }
        let credentials = {
            key: key.toString(),
            cert: cert.toString(),
            passphrase: this.passphrase
        };
        if('' !== this.httpsChain){
            let ca = FileHandler.readFile(this.httpsChain, 'Certificate Authority');
            if(ca){
                credentials.ca = ca;
            }
        }
        return https.createServer(credentials, this.app);
    }

    async enableServeHome(app, homePageLoadCallback)
    {
        let limiterParams = {
            windowMs: this.windowMs,
            max: this.maxRequests,
            standardHeaders: true,
            legacyHeaders: false
        };
        if(this.applyKeyGenerator){
            limiterParams.keyGenerator = function(req){
                return req.ip;
            };
        }
        let limiter = this.rateLimit(limiterParams);
        app.post('/', limiter);
        app.post('/', async (req, res, next) => {
            if('/' === req._parsedUrl.pathname){
                return res.redirect('/');
            }
            next();
        });
        app.get('/', limiter);
        app.get('/', async (req, res, next) => {
            if('/' === req._parsedUrl.pathname){
                if('function' !== typeof homePageLoadCallback){
                    let errorMessage = 'Homepage contents could not be loaded.';
                    if('function' === typeof this.processErrorResponse){
                        return this.processErrorResponse(500, errorMessage, req, res);
                    }
                    return res.status(500).send(errorMessage);
                }
                try {
                    return res.send(await homePageLoadCallback(req));
                } catch(error){
                    let message = 'Error loading homepage.';
                    this.error = {message, error};
                    if('function' === typeof this.processErrorResponse){
                        return this.processErrorResponse(500, message, req, res);
                    }
                    return res.status(500).send(message);
                }
            }
            next();
        });
    }

    async serveStatics(app, statics)
    {
        if(!FileHandler.isValidPath(statics)){
            this.error = {message: 'Invalid statics path.'};
            return;
        }
        let staticOptions = {
            maxAge: '1d',
            etag: true,
            lastModified: true,
            index: false,
            setHeaders: function(res){
                res.set('X-Content-Type-Options', 'nosniff');
            }
        };
        app.use(this.applicationFramework.static(statics, staticOptions));
    }

    async serveStaticsPath(app, staticsPath, statics)
    {
        if(!FileHandler.isValidPath(staticsPath) || !FileHandler.isValidPath(statics)){
            this.error = {message: 'Invalid statics path to be served.'};
            return;
        }
        let staticOptions = {
            maxAge: '1d',
            etag: true,
            lastModified: true,
            index: false,
            setHeaders: function(res){
                res.set('X-Content-Type-Options', 'nosniff');
            }
        };
        app.use(staticsPath, this.applicationFramework.static(statics, staticOptions));
    }

}

module.exports.AppServerFactory = AppServerFactory;
