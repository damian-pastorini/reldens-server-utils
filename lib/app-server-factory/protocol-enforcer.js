/**
 *
 * Reldens - ProtocolEnforcer
 *
 */

const { EventDispatcher } = require('../event-dispatcher');

class ProtocolEnforcer
{

    constructor()
    {
        this.isDevelopmentMode = false;
        this.useHttps = false;
        this.enforceProtocol = true;
        this.onEvent = null;
    }

    setup(app, config)
    {
        this.isDevelopmentMode = config.isDevelopmentMode || false;
        this.useHttps = config.useHttps || false;
        this.enforceProtocol = config.enforceProtocol !== false;
        this.onEvent = config.onEvent || null;
        app.use((req, res, next) => {
            let protocol = String(req.protocol || '').toLowerCase();
            let host = (req.get('host') || '').toLowerCase().trim();
            let isBehindProxy = Boolean(req.get('X-Forwarded-Proto'))
                && req.app.get('trust proxy fn')(req.socket.remoteAddress, 0);
            if(this.isDevelopmentMode){
                res.removeHeader('Origin-Agent-Cluster');
                res.removeHeader('Strict-Transport-Security');
                res.removeHeader('upgrade-insecure-requests');
                res.set('Origin-Agent-Cluster', '?0');
                if(this.enforceProtocol && host && !isBehindProxy){
                    if(!this.useHttps && 'https' === protocol){
                        return res.redirect(301, 'http://'+host+req.url);
                    }
                    if(this.useHttps && 'http' === protocol){
                        return res.redirect(301, 'https://'+host+req.url);
                    }
                }
            }
            res.set('X-Forwarded-Proto', protocol);
            next();
        });
        EventDispatcher.dispatch(
            this.onEvent,
            'protocol-enforcement-enabled',
            'protocolEnforcer',
            this,
            {isDevelopmentMode: this.isDevelopmentMode, useHttps: this.useHttps, enforceProtocol: this.enforceProtocol}
        );
    }

}

module.exports.ProtocolEnforcer = ProtocolEnforcer;
