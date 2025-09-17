/**
 *
 * Reldens - CorsConfigurer
 *
 */

const cors = require('cors');

class CorsConfigurer
{

    constructor()
    {
        this.isDevelopmentMode = false;
        this.useCors = true;
        this.corsOrigin = '*';
        this.corsMethods = ['GET','POST'];
        this.corsHeaders = ['Content-Type','Authorization'];
        this.developmentCorsOrigins = [];
        this.developmentPorts = [];
    }

    setup(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.useCors = config.useCors !== false;
        this.corsOrigin = config.corsOrigin || this.corsOrigin;
        this.corsMethods = config.corsMethods || this.corsMethods;
        this.corsHeaders = config.corsHeaders || this.corsHeaders;
        this.developmentPorts = config.developmentPorts || this.developmentPorts;
        if(!this.useCors){
            return;
        }
        if(this.isDevelopmentMode && config.domainMapping){
            this.developmentCorsOrigins = this.extractDevelopmentOrigins(config.domainMapping);
        }
        let corsOptions = {
            origin: this.corsOrigin,
            methods: this.corsMethods,
            allowedHeaders: this.corsHeaders,
            credentials: true
        };
        if('*' === this.corsOrigin && true === corsOptions.credentials){
            corsOptions.origin = true;
        }
        if(this.isDevelopmentMode && 0 < this.developmentCorsOrigins.length){
            corsOptions.origin = (origin, callback) => {
                if(!origin){
                    return callback(null, true);
                }
                if(-1 !== this.developmentCorsOrigins.indexOf(this.normalizeHost(origin))){
                    return callback(null, true);
                }
                if('*' === this.corsOrigin){
                    return callback(null, true);
                }
                return callback(null, false);
            };
        }
        app.use(cors(corsOptions));
    }

    extractDevelopmentOrigins(domainMapping)
    {
        let originsSet = new Set();
        let mappingKeys = Object.keys(domainMapping);
        for(let domain of mappingKeys){
            let normalizedDomain = this.normalizeHost(domain);
            originsSet.add('http://'+normalizedDomain);
            originsSet.add('https://'+normalizedDomain);
            if(-1 !== normalizedDomain.indexOf(':')){
                continue;
            }
            if(0 < this.developmentPorts.length){
                for(let port of this.developmentPorts){
                    originsSet.add('http://'+normalizedDomain+':'+port);
                    originsSet.add('https://'+normalizedDomain+':'+port);
                }
            }
        }
        return Array.from(originsSet);
    }

    normalizeHost(originOrHost)
    {
        let normalizedHost = (''+originOrHost).toLowerCase();
        if('/' === normalizedHost.charAt(normalizedHost.length - 1)){
            normalizedHost = normalizedHost.substring(0, normalizedHost.length - 1);
        }
        return normalizedHost;
    }

}

module.exports.CorsConfigurer = CorsConfigurer;
