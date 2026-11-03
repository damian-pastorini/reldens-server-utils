/**
 *
 * Reldens - ClientAddressGuard
 *
 */

const proxyaddr = require('proxy-addr');

class ClientAddressGuard
{

    constructor(props)
    {
        this.trustProxyFunction = props.trustProxyFunction;
        this.ipListsConfigurer = props.ipListsConfigurer;
        this.forwardingHeaders = ['x-real-ip', 'x-forwarded-for', 'x-client-ip'];
        this.matchmakePathPrefix = '/matchmake/';
    }

    normalizeRequest(request)
    {
        let address = String(proxyaddr(request, this.trustProxyFunction) || '');
        for(let headerName of this.forwardingHeaders){
            delete request.headers[headerName];
        }
        if('' !== address){
            request.headers['x-real-ip'] = address;
        }
        return address;
    }

    attachToServer(server)
    {
        server.prependListener('upgrade', (request) => this.normalizeRequest(request));
        let requestListeners = server.listeners('request');
        server.removeAllListeners('request');
        server.on('request', (request, response) => this.handleRequest(request, response, requestListeners, server));
        return true;
    }

    handleRequest(request, response, requestListeners, server)
    {
        if(0 === String(request.url || '').indexOf(this.matchmakePathPrefix)){
            if(!this.ipListsConfigurer.isAllowed(this.normalizeRequest(request))){
                response.statusCode = 403;
                return response.end(this.ipListsConfigurer.forbiddenMessage);
            }
        }
        for(let requestListener of requestListeners){
            requestListener.call(server, request, response);
        }
        return true;
    }

}

module.exports.ClientAddressGuard = ClientAddressGuard;
