/**
 *
 * Reldens - EventDispatcher
 *
 */

class EventDispatcher
{

    static dispatch(onEventCallback, eventType, instanceName, instance, data = {})
    {
        if('function' !== typeof onEventCallback){
            return;
        }
        onEventCallback({
            eventType: eventType,
            instanceName: instanceName,
            instance: instance,
            data: data,
            timestamp: new Date().toISOString()
        });
    }

}

module.exports.EventDispatcher = EventDispatcher;
