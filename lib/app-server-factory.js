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

class AppServerFactory
{

    constructor()
    {
        this.applicationFramework = express;
        this.bodyParser = bodyParser;
        this.session = session;
        this.appServer = false;
        this.app = express();
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
        this.errorMessage = '';
    }

    createAppServer(appServerConfig)
    {
        if(appServerConfig){
            Object.assign(this, appServerConfig);
        }
        if(this.useCors){
            this.app.use(cors());
        }
        if(this.useExpressJson){
            this.app.use(this.applicationFramework.json());
        }
        if(this.useUrlencoded){
            this.app.use(this.bodyParser.urlencoded({extended: true}));
        }
        if('' !== this.trustedProxy){
            this.app.enable('trust proxy', this.trustedProxy);
        }
        this.appServer = this.createServer();
        return {app: this.app, appServer: this.appServer};
    }

    createServer()
    {
        if(!this.useHttps){
            return http.createServer(this.app);
        }
        let key = FileHandler.readFile(this.keyPath);
        if(!key){
            this.errorMessage = 'Key file not found: ' + this.keyPath;
            return false;
        }
        let cert = FileHandler.readFile(this.certPath);
        if(!cert){
            this.errorMessage = 'Cert file not found: ' + this.certPath;
            return false;
        }
        let credentials = {
            key: key.toString(),
            cert: cert.toString(),
            passphrase: this.passphrase
        };
        if('' !== this.httpsChain){
            let ca = FileHandler.readFile(this.httpsChain);
            if(ca){
                credentials.ca = ca;
            }
        }
        return https.createServer(credentials, this.app);
    }

    async enableServeHome(app, homePageLoadCallback)
    {
        let limiterParams = {
            // default 60000 = 1 minute:
            windowMs: this.windowMs,
            // limit each IP to 30 requests per windowMs:
            max: this.maxRequests,
        };
        if(this.applyKeyGenerator){
            limiterParams.keyGenerator = function (req) {
                return req.ip;
            };
        }
        let limiter = rateLimit(limiterParams);
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
                    return res.send('Homepage contents could not be loaded.');
                }
                return res.send(await homePageLoadCallback(req));
            }
            next();
        });
    }

    async enableServeStatics(app, staticsPath)
    {
        app.use(this.applicationFramework.static(staticsPath));
    }

}

module.exports.AppServerFactory = AppServerFactory;
