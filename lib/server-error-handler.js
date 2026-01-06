/**
 *
 * Reldens - ServerErrorHandler
 *
 */

class ServerErrorHandler
{

    static handleError(onErrorCallback, instanceName, instance, key, error, context = {})
    {
        if('function' !== typeof onErrorCallback){
            return;
        }
        onErrorCallback({
            [instanceName]: instance,
            key: key,
            error: error,
            ...context
        });
    }

}

module.exports.ServerErrorHandler = ServerErrorHandler;
