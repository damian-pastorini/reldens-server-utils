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
const spdy = require('spdy');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const compression = require('compression');
const tls = require('tls');

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
        this.useHttp2 = false;
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
        this.corsMethods = [];
        this.corsHeaders = [];
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
        this.cacheConfig = {
            '.css': 31536000,
            '.js': 31536000,
            '.woff': 31536000,
            '.woff2': 31536000,
            '.ttf': 31536000,
            '.eot': 31536000,
            '.jpg': 2592000,
            '.jpeg': 2592000,
            '.png': 2592000,
            '.gif': 2592000,
            '.webp': 2592000,
            '.svg': 2592000,
            '.ico': 2592000
        };
        this.staticOptions = {
            maxAge: '1d',
            immutable: false,
            etag: true,
            lastModified: true,
            index: false,
            setHeaders: this.buildStaticHeaders.bind(this)
        };
        this.isDevelopmentMode = false;
        this.developmentDomains = [];
        this.domainMapping = {};
        this.enforceProtocol = true;
        this.developmentPatterns = [];
        this.developmentEnvironments = [];
        this.developmentPorts = [];
        this.developmentMultiplier = 10;
        this.developmentExternalDomains = {};
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

    buildStaticHeaders(res, path)
    {
        res.set('X-Content-Type-Options', 'nosniff');
        res.set('X-Frame-Options', 'DENY');
        res.set('Vary', 'Accept-Encoding');
        let cacheMaxAge = this.getCacheConfigForPath(path);
        if(cacheMaxAge){
            res.set('Cache-Control', 'public, max-age='+cacheMaxAge+', immutable');
        }
    }

    getCacheConfigForPath(path)
    {
        let cacheKeys = Object.keys(this.cacheConfig);
        for(let ext of cacheKeys){
            if(path.endsWith(ext)){
                return this.cacheConfig[ext];
            }
        }
        return false;
    }

    createAppServer(appServerConfig)
    {
        if(appServerConfig){
            Object.assign(this, appServerConfig);
        }
        this.addHttpDomainsAsDevelopment();
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
        try {
            this.appServer = this.createServer();
        } catch (error) {
            this.error = {message: 'Server creation exception: '+error.message};
            return false;
        }
        if(!this.appServer){
            if(!this.error.message){
                this.error = {message: 'The createServer() returned false - check certificate paths and permissions'};
            }
            return false;
        }
        if(this.autoListen){
            this.listen();
        }
        return {app: this.app, appServer: this.appServer};
    }

    extractDomainFromHttpUrl(url)
    {
        if(!url || !url.startsWith('http://')){
            return false;
        }
        return url.replace(/^http:\/\//, '').split(':')[0];
    }

    addHttpDomainsAsDevelopment()
    {
        let hostDomain = this.extractDomainFromHttpUrl(process.env.RELDENS_APP_HOST);
        let publicDomain = this.extractDomainFromHttpUrl(process.env.RELDENS_PUBLIC_URL);
        if(hostDomain && !this.developmentDomains.includes(hostDomain)){
            this.developmentDomains.push(hostDomain);
        }
        if(publicDomain && !this.developmentDomains.includes(publicDomain)){
            this.developmentDomains.push(publicDomain);
        }
    }

    detectDevelopmentMode()
    {
        let detectConfig = {
            developmentDomains: this.developmentDomains,
            domains: this.domains
        };
        if(0 < this.developmentPatterns.length){
            detectConfig['developmentPatterns'] = this.developmentPatterns;
        }
        if(0 < this.developmentEnvironments.length){
            detectConfig['developmentEnvironments'] = this.developmentEnvironments;
        }
        this.isDevelopmentMode = this.developmentModeDetector.detect(detectConfig);
    }

    setupDevelopmentConfiguration()
    {
        if(!this.isDevelopmentMode){
            return;
        }
        this.staticOptions.immutable = false;
        this.staticOptions.setHeaders = (res, path) => {
            res.set('X-Content-Type-Options', 'nosniff');
            res.set('X-Frame-Options', 'SAMEORIGIN');
            res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
            res.set('Vary', 'Accept-Encoding');
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
        let corsConfig = {
            isDevelopmentMode: this.isDevelopmentMode,
            useCors: this.useCors,
            corsOrigin: this.corsOrigin
        };
        if(0 < this.corsMethods.length){
            corsConfig['corsMethods'] = this.corsMethods;
        }
        if(0 < this.corsHeaders.length){
            corsConfig['corsHeaders'] = this.corsHeaders;
        }
        if(0 < this.developmentPorts.length){
            corsConfig['developmentPorts'] = this.developmentPorts;
        }
        if(
            'object' === typeof this.domainMapping
            && null !== this.domainMapping
            && 0 < Object.keys(this.domainMapping)
        ){
            corsConfig['domainMapping'] = this.domainMapping;
        }
        this.corsConfigurer.setup(this.app, corsConfig);
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
            this.app.set('trust proxy', this.trustedProxy);
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
                this.error = {message: 'Unknown domain: '+hostname};
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
        let hostWithoutPort = cleanHostname.split(':')[0];
        for(let i = 0; i < this.domains.length; i++){
            let domain = this.domains[i];
            if(domain.hostname === hostWithoutPort){
                return domain;
            }
            if(domain.aliases && domain.aliases.includes(hostWithoutPort)){
                return domain;
            }
        }
        return false;
    }

    createServer()
    {
        if(!this.useHttps){
            if(this.useHttp2){
                this.error = {message: 'HTTP/2 requires HTTPS to be enabled'};
                return false;
            }
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
        let credentials = {key, cert, passphrase: this.passphrase};
        if('' !== this.httpsChain){
            let ca = FileHandler.readFile(this.httpsChain, 'Certificate Authority');
            if(ca){
                credentials.ca = ca;
            }
        }
        if(this.useHttp2){
            credentials.spdy = {protocols: ['h2', 'http/1.1']};
            return spdy.createServer(credentials, this.app);
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
            let ctx = tls.createSecureContext({key, cert});
            callback(null, ctx);
        };
        if(this.useHttp2){
            httpsOptions.spdy = {protocols: ['h2', 'http/1.1']};
            return spdy.createServer(httpsOptions, this.app);
        }
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

}

module.exports.AppServerFactory = AppServerFactory;
