/**
 *
 * Reldens - DevelopmentModeDetector
 *
 */

const { EventDispatcher } = require('../event-dispatcher');

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
        this.env = process?.env?.NODE_ENV || 'production';
        this.onEvent = null;
    }

    detect(config = {})
    {
        this.onEvent = config.onEvent || null;
        if(config.developmentPatterns){
            this.developmentPatterns = config.developmentPatterns;
        }
        if(config.developmentEnvironments){
            this.developmentEnvironments = config.developmentEnvironments;
        }
        if(this.developmentEnvironments.includes(this.env)){
            EventDispatcher.dispatch(
                this.onEvent,
                'development-mode-detected',
                'developmentModeDetector',
                this,
                {detectionMethod: 'environment', env: this.env}
            );
            return true;
        }
        if(config.developmentDomains && 0 < config.developmentDomains.length){
            for(let domain of config.developmentDomains){
                if(this.matchesPattern(domain)){
                    EventDispatcher.dispatch(
                        this.onEvent,
                        'development-mode-detected',
                        'developmentModeDetector',
                        this,
                        {detectionMethod: 'developmentDomain', domain: domain}
                    );
                    return true;
                }
            }
        }
        if(config.domains && 0 < config.domains.length){
            for(let domainConfig of config.domains){
                if(!domainConfig?.hostname){
                    continue;
                }
                if(this.matchesPattern(domainConfig.hostname)){
                    EventDispatcher.dispatch(
                        this.onEvent,
                        'development-mode-detected',
                        'developmentModeDetector',
                        this,
                        {detectionMethod: 'domainPattern', hostname: domainConfig.hostname}
                    );
                    return true;
                }
            }
        }
        return false;
    }

    matchesPattern(domain)
    {
        if(!domain){
            return false;
        }
        let d = (''+domain).toLowerCase();
        if('localhost' === d){
            return true;
        }
        if('127.0.0.1' === d){
            return true;
        }
        if('::1' === d){
            return true;
        }
        for(let pattern of this.developmentPatterns || []){
            if(!pattern){
                continue;
            }
            let p = (''+pattern).toLowerCase();
            if('.' === p.charAt(0) && d.endsWith(p)){
                return true;
            }
            if('.' === p.charAt(p.length - 1) && 0 === d.indexOf(p)){
                return true;
            }
            if(d === p){
                return true;
            }
            if(0 <= d.indexOf(p)){
                return true;
            }
        }
        return false;
    }

}

module.exports.DevelopmentModeDetector = DevelopmentModeDetector;
