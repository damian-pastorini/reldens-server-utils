/**
 *
 * Reldens - DevelopmentModeDetector
 *
 */

class DevelopmentModeDetector
{

    constructor()
    {
        this.developmentPatterns = [
            'localhost',
            '127.0.0.1',
            // domain ends:
            '.local',
            '.test',
            '.dev',
            '.acc',
            '.staging',
            // sub-domains:
            'local.',
            'test.',
            'dev.',
            'acc.',
            'staging.'
        ];
        this.developmentEnvironments = ['development', 'dev', 'test'];
    }

    detect(config = {})
    {
        if(config.developmentPatterns){
            this.developmentPatterns = config.developmentPatterns;
        }
        if(config.developmentEnvironments){
            this.developmentEnvironments = config.developmentEnvironments;
        }
        let env = process.env.NODE_ENV;
        if(this.developmentEnvironments.includes(env)){
            return true;
        }
        if(config.developmentDomains && 0 < config.developmentDomains.length){
            for(let domain of config.developmentDomains){
                if(this.matchesPattern(domain)){
                    return true;
                }
            }
        }
        if(config.domains && 0 < config.domains.length){
            for(let domainConfig of config.domains){
                if(!domainConfig.hostname){
                    continue;
                }
                if(this.matchesPattern(domainConfig.hostname)){
                    return true;
                }
            }
        }
        return false;
    }

    matchesPattern(domain)
    {
        for(let pattern of this.developmentPatterns){
            if(domain.includes(pattern)){
                return true;
            }
        }
        return false;
    }

}

module.exports.DevelopmentModeDetector = DevelopmentModeDetector;
