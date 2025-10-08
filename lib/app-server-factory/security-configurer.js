/**
 *
 * Reldens - SecurityConfigurer
 *
 */

const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');

class SecurityConfigurer
{

    constructor()
    {
        this.isDevelopmentMode = false;
        this.useHelmet = true;
        this.useXssProtection = true;
        this.helmetConfig = false;
        this.helmetOptions = {};
        this.sanitizeOptions = {allowedTags: [], allowedAttributes: {}};
    }

    setupHelmet(app, config)
    {
        this.useHelmet = config.useHelmet !== false;
        if(!this.useHelmet){
            return;
        }
        app.use(helmet(this.mapHelmetOptions(config)));
    }

    mapHelmetOptions(config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.helmetConfig = config.helmetConfig || {};
        this.helmetOptions = {
            crossOriginEmbedderPolicy: false,
            crossOriginOpenerPolicy: false,
            crossOriginResourcePolicy: false,
            originAgentCluster: false
        };
        if(this.isDevelopmentMode){
            this.helmetOptions.contentSecurityPolicy = false;
            this.helmetOptions.hsts = false;
            this.helmetOptions.noSniff = false;
            return this.helmetOptions;
        }
        this.helmetOptions.contentSecurityPolicy = {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                scriptSrcElem: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                styleSrcElem: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
                fontSrc: ["'self'"],
                connectSrc: ["'self'"],
                frameAncestors: ["'none'"],
                baseUri: ["'self'"],
                formAction: ["'self'"]
            }
        };
        if(this.helmetConfig.contentSecurityPolicy){
            if(this.helmetConfig.contentSecurityPolicy.overrideDirectives){
                this.helmetOptions.contentSecurityPolicy.directives = this.helmetConfig.contentSecurityPolicy.directives;
            }
            if(
                !this.helmetConfig.contentSecurityPolicy.overrideDirectives
                && this.helmetConfig.contentSecurityPolicy.directives
            ){
                let configDirectivesKeys = Object.keys(this.helmetConfig.contentSecurityPolicy.directives);
                for(let directiveKey of configDirectivesKeys){
                    let directiveValues = this.helmetConfig.contentSecurityPolicy.directives[directiveKey];
                    if(!Array.isArray(directiveValues)){
                        continue;
                    }
                    if(!this.helmetOptions.contentSecurityPolicy.directives[directiveKey]){
                        this.helmetOptions.contentSecurityPolicy.directives[directiveKey] = [];
                    }
                    for(let value of directiveValues){
                        this.helmetOptions.contentSecurityPolicy.directives[directiveKey].push(value);
                    }
                }
            }
            let cspKeys = Object.keys(this.helmetConfig.contentSecurityPolicy);
            for(let cspKey of cspKeys){
                if('directives' === cspKey || 'overrideDirectives' === cspKey){
                    continue;
                }
                this.helmetOptions.contentSecurityPolicy[cspKey] = this.helmetConfig.contentSecurityPolicy[cspKey];
            }
        }
        let helmetConfigKeys = Object.keys(this.helmetConfig);
        for(let configKey of helmetConfigKeys){
            if('contentSecurityPolicy' === configKey){
                continue;
            }
            this.helmetOptions[configKey] = this.helmetConfig[configKey];
        }
        if(config.developmentExternalDomains){
            this.addExternalDomainsToCsp(
                this.helmetOptions.contentSecurityPolicy.directives,
                config.developmentExternalDomains
            );
        }
        return this.helmetOptions;
    }

    addExternalDomainsToCsp(directives, externalDomains)
    {
        let keys = Object.keys(externalDomains);
        for(let directiveKey of keys){
            let domains = externalDomains[directiveKey];
            if(!Array.isArray(domains)){
                continue;
            }
            let camelCaseKey = directiveKey.replace(/-([a-z])/g, (match, letter) => letter.toUpperCase());
            for(let domain of domains){
                if(directives[camelCaseKey]){
                    directives[camelCaseKey].push(domain);
                }
                let elemKey = camelCaseKey+'Elem';
                if(directives[elemKey]){
                    directives[elemKey].push(domain);
                }
            }
        }
    }

    setupXssProtection(app, config)
    {
        this.useXssProtection = config.useXssProtection !== false;
        this.sanitizeOptions = config.sanitizeOptions || this.sanitizeOptions;
        if(!this.useXssProtection){
            return;
        }
        app.use((req, res, next) => {
            if(!req.body){
                return next();
            }
            if('object' === typeof req.body && null !== req.body){
                this.sanitizeRequestBody(req.body);
            }
            next();
        });
    }

    sanitizeRequestBody(body)
    {
        if(Array.isArray(body)){
            for(let i = 0; i < body.length; i++){
                if('string' === typeof body[i]){
                    body[i] = sanitizeHtml(body[i], this.sanitizeOptions);
                    continue;
                }
                if('object' === typeof body[i] && null !== body[i]){
                    this.sanitizeRequestBody(body[i]);
                }
            }
            return;
        }
        if('object' !== typeof body || null === body){
            return;
        }
        let keys = Object.keys(body);
        for(let i = 0; i < keys.length; i++){
            let key = keys[i];
            if('string' === typeof body[key]){
                body[key] = sanitizeHtml(body[key], this.sanitizeOptions);
                continue;
            }
            if('object' === typeof body[key] && null !== body[key]){
                this.sanitizeRequestBody(body[key]);
            }
        }
    }

    enableCSP(app, cspOptions)
    {
        let defaults = {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", "data:", "https:"],
            'font-src': ["'self'"],
            'connect-src': ["'self'"],
            'frame-ancestors': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"]
        };
        if(this.isDevelopmentMode){
            defaults['script-src'].push("'unsafe-eval'");
            defaults['connect-src'].push("ws:");
            defaults['connect-src'].push("wss:");
        }
        let csp = Object.assign({}, defaults, cspOptions);
        let policyString = '';
        let keys = Object.keys(csp);
        for(let i = 0; i < keys.length; i++){
            let directive = keys[i];
            let sources = csp[directive];
            if(0 < i){
                policyString += '; ';
            }
            policyString += directive + ' ' + sources.join(' ');
        }
        app.use((req, res, next) => {
            res.setHeader('Content-Security-Policy', policyString);
            next();
        });
        return true;
    }

}

module.exports.SecurityConfigurer = SecurityConfigurer;
