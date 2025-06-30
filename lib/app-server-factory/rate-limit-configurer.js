/**
 *
 * Reldens - RateLimitConfigurer
 *
 */

const rateLimit = require('express-rate-limit');

class RateLimitConfigurer
{

    constructor()
    {
        this.isDevelopmentMode = false;
        this.globalRateLimit = 0;
        this.windowMs = 60000;
        this.maxRequests = 30;
        this.developmentMultiplier = 10;
        this.applyKeyGenerator = false;
        this.tooManyRequestsMessage = 'Too many requests, please try again later.';
        this.rateLimit = rateLimit;
    }

    setup(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.globalRateLimit = config.globalRateLimit || 0;
        this.windowMs = config.windowMs || this.windowMs;
        this.maxRequests = config.maxRequests || this.maxRequests;
        this.developmentMultiplier = config.developmentMultiplier || this.developmentMultiplier;
        this.applyKeyGenerator = config.applyKeyGenerator || false;
        this.tooManyRequestsMessage = config.tooManyRequestsMessage || this.tooManyRequestsMessage;
        if(!this.globalRateLimit){
            return;
        }
        let limiterParams = {
            windowMs: this.windowMs,
            max: this.maxRequests,
            standardHeaders: true,
            legacyHeaders: false,
            message: this.tooManyRequestsMessage
        };
        if(this.isDevelopmentMode){
            limiterParams.max = this.maxRequests * this.developmentMultiplier;
        }
        if(this.applyKeyGenerator){
            limiterParams.keyGenerator = function(req){
                return req.ip;
            };
        }
        app.use(this.rateLimit(limiterParams));
    }

    createHomeLimiter()
    {
        let limiterParams = {
            windowMs: this.windowMs,
            max: this.maxRequests,
            standardHeaders: true,
            legacyHeaders: false
        };
        if(this.isDevelopmentMode){
            limiterParams.max = this.maxRequests * this.developmentMultiplier;
        }
        if(this.applyKeyGenerator){
            limiterParams.keyGenerator = function(req){
                return req.ip;
            };
        }
        return this.rateLimit(limiterParams);
    }

}

module.exports.RateLimitConfigurer = RateLimitConfigurer;
