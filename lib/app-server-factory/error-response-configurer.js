/**
 *
 * Reldens - ErrorResponseConfigurer
 *
 */

const http = require('http');
const { ServerErrorHandler } = require('../server-error-handler');
const { EventDispatcher } = require('../event-dispatcher');

class ErrorResponseConfigurer
{

    constructor()
    {
        this.serverErrorStatus = 500;
        this.clientErrorStatus = 400;
        this.processErrorResponse = false;
        this.onError = null;
        this.onEvent = null;
    }

    setup(app, config)
    {
        this.processErrorResponse = config.processErrorResponse || false;
        this.onError = config.onError || null;
        this.onEvent = config.onEvent || null;
        app.use(this.respondError.bind(this));
        EventDispatcher.dispatch(
            this.onEvent,
            'error-response-enabled',
            'errorResponseConfigurer',
            this,
            {hasProcessErrorResponse: 'function' === typeof this.processErrorResponse}
        );
    }

    respondError(error, req, res, next)
    {
        let statusCode = this.fetchStatusCode(error);
        ServerErrorHandler.handleError(
            this.onError,
            'errorResponseConfigurer',
            this,
            'request-error',
            error,
            {request: req, response: res, statusCode: statusCode, path: req.path}
        );
        if(res.headersSent || 'function' !== typeof this.processErrorResponse){
            return next(error);
        }
        return this.processErrorResponse(statusCode, http.STATUS_CODES[statusCode], req, res);
    }

    fetchStatusCode(error)
    {
        let statusCode = Number(error?.status || error?.statusCode);
        if(this.clientErrorStatus <= statusCode && this.serverErrorStatus > statusCode){
            return statusCode;
        }
        return this.serverErrorStatus;
    }

}

module.exports.ErrorResponseConfigurer = ErrorResponseConfigurer;
