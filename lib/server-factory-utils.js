/**
 *
 * Reldens - ServerFactoryUtils
 *
 */

class ServerFactoryUtils
{

    static getCacheConfigForPath(path, cacheConfig)
    {
        if(!cacheConfig){
            return false;
        }
        let cacheKeys = Object.keys(cacheConfig);
        for(let ext of cacheKeys){
            if(path.endsWith(ext)){
                return cacheConfig[ext];
            }
        }
        return false;
    }

    static validateOrigin(origin, corsOrigins, corsAllowAll)
    {
        if(corsAllowAll){
            return '*';
        }
        if(!origin){
            return false;
        }
        if(0 === corsOrigins.length){
            return false;
        }
        for(let allowedOrigin of corsOrigins){
            if('string' === typeof allowedOrigin && origin === allowedOrigin){
                return origin;
            }
            if(allowedOrigin instanceof RegExp && allowedOrigin.test(origin)){
                return origin;
            }
        }
        return false;
    }

    static stripQueryString(url)
    {
        if(!url){
            return '';
        }
        return url.split('?')[0];
    }

}

module.exports.ServerFactoryUtils = ServerFactoryUtils;
