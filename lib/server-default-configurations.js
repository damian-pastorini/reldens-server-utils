/**
 *
 * Reldens - ServerDefaultConfigurations
 *
 */

class ServerDefaultConfigurations
{

    static get mimeTypes()
    {
        return {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.txt': 'text/plain',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
            '.ttf': 'font/ttf',
            '.eot': 'application/vnd.ms-fontobject',
            '.webmanifest': 'application/manifest+json'
        };
    }

    static get cacheConfig()
    {
        return {
            '.css': 31536000,
            '.js': 31536000,
            '.woff': 31536000,
            '.woff2': 31536000,
            '.ttf': 31536000,
            '.eot': 31536000,
            '.jpg': 2592000,
            '.jpeg': 2592000,
            '.png': 2592000,
            '.gif': 2592000,
            '.webp': 2592000,
            '.svg': 2592000,
            '.ico': 2592000,
            '.xml': 31536000,
            '.webmanifest': 31536000
        };
    }

}

module.exports.ServerDefaultConfigurations = ServerDefaultConfigurations;
