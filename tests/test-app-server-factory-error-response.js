/**
 *
 * Reldens - Server Utils - TestAppServerFactoryErrorResponse
 *
 */

const { BaseTest } = require('./base-test');
const { LocalHttpExchange } = require('./local-http-exchange');
const { AppServerFactoryTestBuilder } = require('./app-server-factory-test-builder');

class TestAppServerFactoryErrorResponse extends BaseTest
{

    constructor()
    {
        super();
        this.localHttpExchange = new LocalHttpExchange();
        this.builder = new AppServerFactoryTestBuilder();
        this.failingPath = '/failing';
        this.asyncFailingPath = '/async-failing';
        this.customResponsePrefix = 'custom:';
        this.customErrorResponse = (statusCode, message, req, res) => res.status(statusCode).send(
            this.customResponsePrefix+message
        );
        this.malformedJsonRequest = {
            path: this.builder.echoPath,
            method: 'POST',
            headers: {'Content-Type': this.localHttpExchange.jsonContentType}
        };
    }

    createErrorResponseFactory(appServerConfig)
    {
        let reportedErrors = [];
        let appServerFactory = this.builder.createFactory(Object.assign({
            onError: (errorEvent) => reportedErrors.push(errorEvent)
        }, appServerConfig));
        appServerFactory.app.get(this.failingPath, (req, res, next) => next(new Error('Route failure')));
        appServerFactory.app.get(this.asyncFailingPath, () => Promise.reject(new Error('Async route failure')));
        appServerFactory.enableErrorResponse(appServerFactory.app);
        return {appServerFactory, reportedErrors};
    }

    async testTheApplicationEnvironmentDefaultsToProduction()
    {
        await this.test('createAppServer sets the application environment, production by default', () => {
            let defaultFactory = this.builder.createFactory({});
            let developmentFactory = this.builder.createFactory({applicationEnvironment: 'development'});
            this.assert.strictEqual(defaultFactory.app.get('env'), 'production');
            this.assert.strictEqual(developmentFactory.app.get('env'), 'development');
        });
    }

    async testAMalformedJsonBodyAnswersTheParserStatusWithoutTheStack()
    {
        await this.test('a malformed JSON body reaches onError and answers 400 without the error stack', async () => {
            let errorResponseFactory = this.createErrorResponseFactory({});
            let response = await this.localHttpExchange.requestServer(
                errorResponseFactory.appServerFactory.appServer,
                this.malformedJsonRequest,
                '{"broken":'
            );
            let reportedError = errorResponseFactory.reportedErrors.shift();
            this.assert.strictEqual(response.statusCode, 400);
            this.assert.strictEqual(String(response.body).includes('SyntaxError'), false);
            this.assert.strictEqual(reportedError.key, 'request-error');
            this.assert.strictEqual(reportedError.statusCode, 400);
        });
    }

    async testARouteErrorAnswersThroughProcessErrorResponse()
    {
        await this.test('a route error reaches onError and answers 500 through processErrorResponse', async () => {
            let errorResponseFactory = this.createErrorResponseFactory({
                processErrorResponse: this.customErrorResponse
            });
            let response = await this.localHttpExchange.requestServer(
                errorResponseFactory.appServerFactory.appServer,
                {path: this.failingPath}
            );
            let reportedError = errorResponseFactory.reportedErrors.shift();
            this.assert.strictEqual(response.statusCode, 500);
            this.assert.strictEqual(String(response.body), this.customResponsePrefix+'Internal Server Error');
            this.assert.strictEqual(reportedError.error.message, 'Route failure');
            this.assert.strictEqual(reportedError.path, this.failingPath);
        });
    }

    async testARejectedAsyncRouteReachesTheErrorResponse()
    {
        await this.test('a rejected async route reaches onError and answers 500', async () => {
            let errorResponseFactory = this.createErrorResponseFactory({});
            let response = await this.localHttpExchange.requestServer(
                errorResponseFactory.appServerFactory.appServer,
                {path: this.asyncFailingPath}
            );
            let reportedError = errorResponseFactory.reportedErrors.shift();
            this.assert.strictEqual(response.statusCode, 500);
            this.assert.strictEqual(String(response.body).includes('Async route failure'), false);
            this.assert.strictEqual(reportedError.error.message, 'Async route failure');
        });
    }

}

module.exports.TestAppServerFactoryErrorResponse = TestAppServerFactoryErrorResponse;
