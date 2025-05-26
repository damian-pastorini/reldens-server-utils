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
        this.port = 3000;
        this.autoListen = false;
        this.domains = [];
        this.useVirtualHosts = false;
        this.defaultDomain = '';
    }

    createAppServer(appServerConfig)
    {
        if(appServerConfig){
            Object.assign(this, appServerConfig);
        }
        if(this.useHelmet){
            this.app.use(this.helmetConfig ? helmet(this.helmetConfig) : helmet());
        }
        if(this.useVirtualHosts){
            this.setupVirtualHosts();
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
                if('object' === typeof req.body){
                    let bodyKeys = Object.keys(req.body);
                    for(let i = 0; i < bodyKeys.length; i++){
                        let key = bodyKeys[i];
                        if('string' === typeof req.body[key]){
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
                verify: this.verifyContentTypeJson.bind(this)
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
        if(!this.appServer){
            this.error = {message: 'Failed to create app server'};
            return false;
        }
        if(this.autoListen){
            this.listen();
        }
        return {app: this.app, appServer: this.appServer};
    }

    verifyContentTypeJson(req, res, buf)
    {
        let contentType = req.headers['content-type'] || '';
        if(
            'POST' === req.method
            && 0 < buf.length
            && !contentType.includes('application/json')
            && !contentType.includes('multipart/form-data')
        ){
            this.error = {message: 'Invalid content-type for JSON request'};
            return false;
        }
    }

    setupVirtualHosts()
    {
        if(0 === this.domains.length){
            return;
        }
        this.app.use((req, res, next) => {
            let hostname = req.get('host');
            if(!hostname){
                if(this.defaultDomain){
                    req.domain = this.defaultDomain;
                    return next();
                }
                this.error = {message: 'No hostname provided and no default domain configured'};
                return res.status(400).send('Bad Request');
            }
            let domain = this.findDomainConfig(hostname);
            if(!domain){
                if(this.defaultDomain){
                    req.domain = this.defaultDomain;
                    return next();
                }
                this.error = {message: 'Unknown domain: '+hostname};
                return res.status(404).send('Domain not found');
            }
            req.domain = domain;
            next();
        });
    }

    findDomainConfig(hostname)
    {
        for(let i = 0; i < this.domains.length; i++){
            let domain = this.domains[i];
            if(domain.hostname === hostname){
                return domain;
            }
            if(domain.aliases && domain.aliases.includes(hostname)){
                return domain;
            }
        }
        return false;
    }

    createServer()
    {
        if(!this.useHttps){
            return http.createServer(this.app);
        }
        if(this.useVirtualHosts && 0 < this.domains.length){
            return this.createHttpsServerWithSNI();
        }
        return this.createSingleHttpsServer();
    }

    createSingleHttpsServer()
    {
        let key = FileHandler.readFile(this.keyPath, 'Key');
        if(!key){
            this.error = {message: 'Could not read SSL key file: '+this.keyPath};
            return false;
        }
        let cert = FileHandler.readFile(this.certPath, 'Cert');
        if(!cert){
            this.error = {message: 'Could not read SSL certificate file: '+this.certPath};
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

    createHttpsServerWithSNI()
    {
        let defaultCredentials = this.loadDefaultCredentials();
        if(!defaultCredentials){
            return false;
        }
        let httpsOptions = Object.assign({}, defaultCredentials);
        httpsOptions.SNICallback = (hostname, callback) => {
            let domain = this.findDomainConfig(hostname);
            if(!domain || !domain.keyPath || !domain.certPath){
                return callback(null, null);
            }
            let key = FileHandler.readFile(domain.keyPath, 'Domain Key');
            if(!key){
                this.error = {message: 'Could not read domain SSL key: '+domain.keyPath};
                return callback(null, null);
            }
            let cert = FileHandler.readFile(domain.certPath, 'Domain Cert');
            if(!cert){
                this.error = {message: 'Could not read domain SSL certificate: '+domain.certPath};
                return callback(null, null);
            }
            let ctx = require('tls').createSecureContext({
                key: key.toString(),
                cert: cert.toString()
            });
            callback(null, ctx);
        };
        return https.createServer(httpsOptions, this.app);
    }

    loadDefaultCredentials()
    {
        let key = FileHandler.readFile(this.keyPath, 'Default Key');
        if(!key){
            this.error = {message: 'Could not read default SSL key file: '+this.keyPath};
            return false;
        }
        let cert = FileHandler.readFile(this.certPath, 'Default Cert');
        if(!cert){
            this.error = {message: 'Could not read default SSL certificate file: '+this.certPath};
            return false;
        }
        return {
            key: key.toString(),
            cert: cert.toString(),
            passphrase: this.passphrase
        };
    }

    listen(port)
    {
        let listenPort = port || this.port;
        if(!this.appServer){
            this.error = {message: 'Cannot listen: app server not created'};
            return false;
        }
        this.appServer.listen(listenPort);
        return true;
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
                let homepageContent = await homePageLoadCallback(req);
                if(!homepageContent){
                    let message = 'Error loading homepage content';
                    this.error = {message};
                    if('function' === typeof this.processErrorResponse){
                        return this.processErrorResponse(500, message, req, res);
                    }
                    return res.status(500).send(message);
                }
                return res.send(homepageContent);
            }
            next();
        });
    }

    async serveStatics(app, statics)
    {
        if(!FileHandler.isValidPath(statics)){
            this.error = {message: 'Invalid statics path: '+statics};
            return false;
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
        return true;
    }

    async serveStaticsPath(app, staticsPath, statics)
    {
        if(!FileHandler.isValidPath(staticsPath) || !FileHandler.isValidPath(statics)){
            this.error = {message: 'Invalid statics path to be served: '+staticsPath+' -> '+statics};
            return false;
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
        return true;
    }

    addDomain(domainConfig)
    {
        if(!domainConfig.hostname){
            this.error = {message: 'Domain configuration missing hostname'};
            return false;
        }
        this.domains.push(domainConfig);
        return true;
    }

    async close()
    {
        if(!this.appServer){
            return true;
        }
        return await this.appServer.close();
    }

}

module.exports.AppServerFactory = AppServerFactory;
