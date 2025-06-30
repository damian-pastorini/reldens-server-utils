/**
 *
 * Reldens - ProtocolEnforcer
 *
 */

class ProtocolEnforcer
{

    constructor()
    {
        this.isDevelopmentMode = false;
        this.useHttps = false;
        this.enforceProtocol = true;
    }

    setup(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.useHttps = config.useHttps || false;
        this.enforceProtocol = config.enforceProtocol !== false;
        app.use((req, res, next) => {
            let protocol = req.get('X-Forwarded-Proto') || req.protocol;
            let host = req.get('host');
            if(this.isDevelopmentMode){
                res.removeHeader('Origin-Agent-Cluster');
                res.removeHeader('Strict-Transport-Security');
                res.removeHeader('upgrade-insecure-requests');
                res.set('Origin-Agent-Cluster', '?0');
                if(this.enforceProtocol && host){
                    if(!this.useHttps && 'https' === protocol){
                        let redirectUrl = 'http://'+host+req.url;
                        return res.redirect(301, redirectUrl);
                    }
                    if(this.useHttps && 'http' === protocol){
                        let redirectUrl = 'https://'+host+req.url;
                        return res.redirect(301, redirectUrl);
                    }
                }
            }
            res.set('X-Forwarded-Proto', protocol);
            next();
        });
    }

}

module.exports.ProtocolEnforcer = ProtocolEnforcer;
