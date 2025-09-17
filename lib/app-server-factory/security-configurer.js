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
        this.sanitizeOptions = {allowedTags: [], allowedAttributes: {}};
    }

    setupHelmet(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.useHelmet = config.useHelmet !== false;
        this.helmetConfig = config.helmetConfig || false;
        if(!this.useHelmet){
            return;
        }
        let helmetOptions = this.setModeOptions({
            crossOriginEmbedderPolicy: false,
            crossOriginOpenerPolicy: false,
            crossOriginResourcePolicy: false,
            originAgentCluster: false
        }, config);
        if(this.helmetConfig){
            Object.assign(helmetOptions, this.helmetConfig);
        }
        app.use(helmet(helmetOptions));
    }

    setModeOptions(helmetOptions, config)
    {
        if(this.isDevelopmentMode){
            helmetOptions.contentSecurityPolicy = false;
            helmetOptions.hsts = false;
            helmetOptions.noSniff = false;
            return helmetOptions;
        }
        helmetOptions.contentSecurityPolicy = {
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
        if(config.developmentExternalDomains){
            this.addExternalDomainsToCsp(
                helmetOptions.contentSecurityPolicy.directives,
                config.developmentExternalDomains
            );
        }
        return helmetOptions;
    }

    addExternalDomainsToCsp(directives, externalDomains)
    {
        let keys = Object.keys(externalDomains);
        for(let directiveKey of keys){
            let domains = externalDomains[directiveKey];
            if(!Array.isArray(domains)){
                continue;
            }
            for(let domain of domains){
                if(directives[directiveKey]){
                    directives[directiveKey].push(domain);
                }
                let elemKey = directiveKey.replace('-src', '-src-elem');
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
