/**
 *
 * Reldens - RateLimitConfigurer
 *
 */

const rateLimit = require('express-rate-limit');
const { EventDispatcher } = require('../event-dispatcher');

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
        this.onEvent = null;
    }

    setup(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.globalRateLimit = config.globalRateLimit || 0;
        this.windowMs = Number(config.windowMs || this.windowMs);
        this.maxRequests = Number(config.maxRequests || this.maxRequests);
        this.developmentMultiplier = Number(config.developmentMultiplier || this.developmentMultiplier);
        this.applyKeyGenerator = config.applyKeyGenerator || false;
        this.tooManyRequestsMessage = config.tooManyRequestsMessage || this.tooManyRequestsMessage;
        this.onEvent = config.onEvent || null;
        if(!this.globalRateLimit){
            return;
        }
        let limiterParams = {
            windowMs: this.windowMs,
            limit: this.maxRequests,
            standardHeaders: 'draft-8',
            legacyHeaders: false,
            message: this.tooManyRequestsMessage
        };
        if(this.isDevelopmentMode){
            limiterParams.limit = this.maxRequests * this.developmentMultiplier;
        }
        if(this.applyKeyGenerator){
            limiterParams.keyGenerator = function(req){
                return rateLimit.ipKeyGenerator(req.ip);
            };
        }
        app.use(this.rateLimit(limiterParams));
        EventDispatcher.dispatch(
            this.onEvent,
            'rate-limiting-configured',
            'rateLimitConfigurer',
            this,
            {globalRateLimit: this.globalRateLimit, maxRequests: limiterParams.limit, windowMs: this.windowMs}
        );
    }

    createHomeLimiter()
    {
        let limiterParams = {
            windowMs: this.windowMs,
            limit: this.maxRequests,
            standardHeaders: 'draft-8',
            legacyHeaders: false
        };
        if(this.isDevelopmentMode){
            limiterParams.limit = this.maxRequests * this.developmentMultiplier;
        }
        if(this.applyKeyGenerator){
            limiterParams.keyGenerator = function(req){
                return rateLimit.ipKeyGenerator(req.ip);
            };
        }
        return this.rateLimit(limiterParams);
    }

}

module.exports.RateLimitConfigurer = RateLimitConfigurer;
