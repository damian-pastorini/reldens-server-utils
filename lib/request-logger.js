/**
 *
 * Reldens - RequestLogger
 *
 */

class RequestLogger
{

    static createMiddleware(onRequestSuccess, onRequestError)
    {
        return (req, res, next) => {
            let startTime = Date.now();
            res.on('finish', () => {
                let responseTime = Date.now()-startTime;
                let requestData = {
                    method: req.method,
                    path: req.originalUrl,
                    statusCode: res.statusCode,
                    responseTime: responseTime,
                    ip: req.headers['x-forwarded-for'] || req.ip,
                    userAgent: req.get('user-agent'),
                    hostname: req.headers['x-forwarded-host'] || req.get('host'),
                    timestamp: new Date().toISOString()
                };
                if(400 <= res.statusCode){
                    if('function' === typeof onRequestError){
                        onRequestError(requestData);
                    }
                    return;
                }
                if('function' === typeof onRequestSuccess){
                    onRequestSuccess(requestData);
                }
            });
            next();
        };
    }

}

module.exports.RequestLogger = RequestLogger;
