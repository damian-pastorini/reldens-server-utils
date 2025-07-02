/**
 *
 * Reldens - AppServerFactory
 *
 */

const { FileHandler } = require('./file-handler');
const { DevelopmentModeDetector } = require('./app-server-factory/development-mode-detector');
const { ProtocolEnforcer } = require('./app-server-factory/protocol-enforcer');
const { SecurityConfigurer } = require('./app-server-factory/security-configurer');
const { CorsConfigurer } = require('./app-server-factory/cors-configurer');
const { RateLimitConfigurer } = require('./app-server-factory/rate-limit-configurer');
const http = require('http');
const https = require('https');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const compression = require('compression');

class AppServerFactory
{

    constructor()
    {
        this.applicationFramework = express;
        this.bodyParser = bodyParser;
        this.session = session;
        this.compression = compression;
        this.appServer = false;
        this.app = express();
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
        this.maxRequestSize = '10mb';
        this.sanitizeOptions = {allowedTags: [], allowedAttributes: {}};
        this.staticOptions = {
            maxAge: '1d',
            etag: true,
            lastModified: true,
            index: false,
            setHeaders: function(res){
                res.set('X-Content-Type-Options', 'nosniff');
                res.set('X-Frame-Options', 'DENY');
            }
        };
        this.isDevelopmentMode = false;
        this.developmentDomains = [];
        this.domainMapping = {};
        this.enforceProtocol = true;
        this.developmentPatterns = [
            'localhost',
            '127.0.0.1',
            '.local',
            '.test',
            '.dev',
            '.staging'
        ];
        this.developmentEnvironments = ['development', 'dev', 'test'];
        this.developmentPorts = [3000, 8080, 8081];
        this.developmentMultiplier = 10;
        this.developmentModeDetector = new DevelopmentModeDetector();
        this.protocolEnforcer = new ProtocolEnforcer();
        this.securityConfigurer = new SecurityConfigurer();
        this.corsConfigurer = new CorsConfigurer();
        this.rateLimitConfigurer = new RateLimitConfigurer();
        this.useCompression = true;
        this.compressionOptions = {
            level: 6,
            threshold: 1024,
            filter: function(req, res){
                if(req.headers['x-no-compression']){
                    return false;
                }
                return compression.filter(req, res);
            }
        };
    }

    createAppServer(appServerConfig)
    {
        if(appServerConfig){
            Object.assign(this, appServerConfig);
        }
        this.detectDevelopmentMode();
        this.setupDevelopmentConfiguration();
        this.setupProtocolEnforcement();
        this.setupSecurity();
        this.setupCompression();
        this.setupVirtualHosts();
        this.setupCors();
        this.setupRateLimiting();
        this.setupRequestParsing();
        this.setupTrustedProxy();
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

    detectDevelopmentMode()
    {
        this.isDevelopmentMode = this.developmentModeDetector.detect({
            developmentPatterns: this.developmentPatterns,
            developmentEnvironments: this.developmentEnvironments,
            developmentDomains: this.developmentDomains,
            domains: this.domains
        });
    }

    setupDevelopmentConfiguration()
    {
        if(!this.isDevelopmentMode){
            return;
        }
        this.staticOptions.setHeaders = (res, path) => {
            res.set('X-Content-Type-Options', 'nosniff');
            res.set('X-Frame-Options', 'SAMEORIGIN');
            res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
        };
    }

    setupProtocolEnforcement()
    {
        this.protocolEnforcer.setup(this.app, {
            isDevelopmentMode: this.isDevelopmentMode,
            useHttps: this.useHttps,
            enforceProtocol: this.enforceProtocol
        });
    }

    setupSecurity()
    {
        this.securityConfigurer.setupHelmet(this.app, {
            isDevelopmentMode: this.isDevelopmentMode,
            useHelmet: this.useHelmet,
            helmetConfig: this.helmetConfig,
            developmentExternalDomains: this.developmentExternalDomains
        });
        this.securityConfigurer.setupXssProtection(this.app, {
            useXssProtection: this.useXssProtection,
            sanitizeOptions: this.sanitizeOptions
        });
    }

    setupCompression()
    {
        if(!this.useCompression){
            return;
        }
        this.app.use(this.compression(this.compressionOptions));
    }

    setupCors()
    {
        this.corsConfigurer.setup(this.app, {
            isDevelopmentMode: this.isDevelopmentMode,
            useCors: this.useCors,
            corsOrigin: this.corsOrigin,
            corsMethods: this.corsMethods,
            corsHeaders: this.corsHeaders,
            domainMapping: this.domainMapping,
            developmentPorts: this.developmentPorts
        });
    }

    setupRateLimiting()
    {
        this.rateLimitConfigurer.setup(this.app, {
            isDevelopmentMode: this.isDevelopmentMode,
            globalRateLimit: this.globalRateLimit,
            windowMs: this.windowMs,
            maxRequests: this.maxRequests,
            developmentMultiplier: this.developmentMultiplier,
            applyKeyGenerator: this.applyKeyGenerator,
            tooManyRequestsMessage: this.tooManyRequestsMessage
        });
    }

    setupRequestParsing()
    {
        if(this.maxRequestSize){
            this.jsonLimit = this.maxRequestSize;
            this.urlencodedLimit = this.maxRequestSize;
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
    }

    setupTrustedProxy()
    {
        if('' !== this.trustedProxy){
            this.app.enable('trust proxy', this.trustedProxy);
        }
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
        if(!this.useVirtualHosts || 0 === this.domains.length){
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
                this.error = {message: 'Unknown domain: ' + hostname};
                return res.status(404).send('Domain not found');
            }
            req.domain = domain;
            next();
        });
    }

    findDomainConfig(hostname)
    {
        if(!hostname || 'string' !== typeof hostname){
            return false;
        }
        let cleanHostname = hostname.toLowerCase().trim();
        for(let i = 0; i < this.domains.length; i++){
            let domain = this.domains[i];
            if(domain.hostname === cleanHostname){
                return domain;
            }
            if(domain.aliases && domain.aliases.includes(cleanHostname)){
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
            this.error = {message: 'Could not read SSL key file: ' + this.keyPath};
            return false;
        }
        let cert = FileHandler.readFile(this.certPath, 'Cert');
        if(!cert){
            this.error = {message: 'Could not read SSL certificate file: ' + this.certPath};
            return false;
        }
        let credentials = {key, cert, passphrase: this.passphrase};
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
            let ctx = require('tls').createSecureContext({key, cert});
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
        return {key, cert, passphrase: this.passphrase};
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
        let limiter = this.rateLimitConfigurer.createHomeLimiter();
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
        app.use(this.applicationFramework.static(statics, this.staticOptions));
        return true;
    }

    async serveStaticsPath(app, staticsPath, statics)
    {
        app.use(staticsPath, this.applicationFramework.static(statics, this.staticOptions));
        return true;
    }

    addDomain(domainConfig)
    {
        if(!domainConfig || !domainConfig.hostname){
            this.error = {message: 'Domain configuration missing hostname'};
            return false;
        }
        if('string' !== typeof domainConfig.hostname){
            this.error = {message: 'Domain hostname must be a string'};
            return false;
        }
        this.domains.push(domainConfig);
        return true;
    }

    addDevelopmentDomain(domain)
    {
        if(!domain || 'string' !== typeof domain){
            return false;
        }
        this.developmentDomains.push(domain);
        return true;
    }

    setDomainMapping(mapping)
    {
        if(!mapping || 'object' !== typeof mapping){
            return false;
        }
        this.domainMapping = mapping;
        return true;
    }

    async close()
    {
        if(!this.appServer){
            return true;
        }
        return this.appServer.close();
    }

    enableCSP(cspOptions)
    {
        return this.securityConfigurer.enableCSP(this.app, cspOptions);
    }

    validateInput(input, type)
    {
        if('string' !== typeof input){
            return false;
        }
        let patterns = {
            email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            username: /^[a-zA-Z0-9_-]{3,30}$/,
            strongPassword: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
            alphanumeric: /^[a-zA-Z0-9]+$/,
            numeric: /^\d+$/,
            hexColor: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,
            ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
        };
        return patterns[type] ? patterns[type].test(input) : false;
    }

}

module.exports.AppServerFactory = AppServerFactory;
