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
const sanitizeHtml = require('sanitize-html');

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
        this.useCors = true;
        this.useExpressJson = true;
        this.useUrlencoded = true;
        this.encoding = 'utf-8';
        this.useHttps = false;
        this.passphrase = '';
        this.httpsChain = '';
        this.keyPath = '';
        this.certPath = '';
        this.trustedProxy = '';
        this.windowMs = 60000;
        this.maxRequests = 30;
        this.applyKeyGenerator = false;
        this.jsonLimit = '1mb';
        this.urlencodedLimit = '1mb';
        this.useHelmet = true;
        this.helmetConfig = false;
        this.useXssProtection = true;
        this.globalRateLimit = 0;
        this.corsOrigin = '*';
        this.corsMethods = ['GET','POST'];
        this.corsHeaders = ['Content-Type','Authorization'];
        this.tooManyRequestsMessage = 'Too many requests, please try again later.';
        this.error = {};
        this.processErrorResponse = false;
    }

    createAppServer(appServerConfig)
    {
        if(appServerConfig){
            Object.assign(this, appServerConfig);
        }
        if(this.useHelmet){
            this.app.use(this.helmetConfig ? helmet(this.helmetConfig) : helmet());
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
            this.app.use((req, res, next) => {
                if(!req.body){
                    return next();
                }
                if(typeof req.body === 'object'){
                    for(let key in req.body){
                        if(typeof req.body[key] === 'string'){
                            req.body[key] = sanitizeHtml(req.body[key]);
                        }
                    }
                }
                next();
            });
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
