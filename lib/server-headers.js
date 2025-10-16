/**
 *
 * Reldens - ServerHeaders
 *
 */

class ServerHeaders
{

    constructor()
    {
        this.http2SecurityHeaders = {
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY'
        };
        this.http2VaryHeader = 'Accept-Encoding, Origin';
        this.http2CorsMethods = 'GET, OPTIONS';
        this.http2CorsHeaders = 'Content-Type';
        this.expressSecurityHeaders = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY'
        };
        this.expressVaryHeader = 'Accept-Encoding';
        this.expressCacheControlNoCache = 'no-cache, no-store, must-revalidate';
        this.expressCacheControlPublic = 'public, max-age={maxAge}, immutable';
        this.expressPragma = 'no-cache';
        this.expressExpires = '0';
    }

    buildCacheControlHeader(maxAge)
    {
        return this.expressCacheControlPublic.replace('{maxAge}', maxAge);
    }

}

module.exports.ServerHeaders = ServerHeaders;
