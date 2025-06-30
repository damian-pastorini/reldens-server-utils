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
        this.developmentPorts = [3000, 8080, 8081];
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
        if(this.isDevelopmentMode && 0 < this.developmentCorsOrigins.length){
            corsOptions.origin = (origin, callback) => {
                if(!origin){
                    return callback(null, true);
                }
                if(-1 !== this.developmentCorsOrigins.indexOf(origin)){
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
        let origins = [];
        let mappingKeys = Object.keys(domainMapping);
        for(let domain of mappingKeys){
            origins.push('http://'+domain);
            origins.push('https://'+domain);
            if(domain.includes(':')){
                continue;
            }
            for(let port of this.developmentPorts){
                origins.push('http://'+domain+':'+port);
                origins.push('https://'+domain+':'+port);
            }
        }
        return origins;
    }

}

module.exports.CorsConfigurer = CorsConfigurer;
