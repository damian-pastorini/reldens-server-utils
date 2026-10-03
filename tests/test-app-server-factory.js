/**
 *
 * Reldens - Server Utils - TestAppServerFactory
 *
 */

const http = require('http');
const zlib = require('zlib');
const sanitizeHtml = require('sanitize-html');
const { BaseTest } = require('./base-test');
const { LocalHttpExchange } = require('./local-http-exchange');
const { AppServerFactoryTestBuilder } = require('./app-server-factory-test-builder');
const { AppServerFactory } = require('../lib/app-server-factory');
const { FileHandler } = require('../lib/file-handler');
const { ServerDefaultConfigurations } = require('../lib/server-default-configurations');

class TestAppServerFactory extends BaseTest
{

    constructor()
    {
        super();
        this.localHttpExchange = new LocalHttpExchange();
        this.builder = new AppServerFactoryTestBuilder();
        this.developmentDomain = 'localhost';
        this.clientOrigin = 'http://client.example.com';
        this.missingPath = '/missing';
        this.staticsPath = '/assets';
        this.staticFileName = 'base-test.js';
        this.homeContent = 'Reldens homepage';
        this.urlencodedBody = 'name=Player&level=3';
        this.jsonHeaders = {'Content-Type': this.localHttpExchange.jsonContentType};
        this.missingKeyPath = FileHandler.joinPaths(this.builder.testsPath, 'missing-key.pem');
    }

    async fetchStaticFile(appServerConfig)
    {
        let appServerFactory = this.builder.createFactory(appServerConfig);
        await appServerFactory.serveStaticsPath(appServerFactory.app, this.staticsPath, this.builder.testsPath);
        return {
            serverHeaders: appServerFactory.serverHeaders,
            response: await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.staticsPath+'/'+this.staticFileName}
            )
        };
    }

    async testTheCreateAppServerReturnsTheHttpServerAndDispatchesTheSetupEvents()
    {
        await this.test('createAppServer returns the http server and dispatches the setup events in order', () => {
            let dispatchedEvents = [];
            let appServerFactory = new AppServerFactory();
            appServerFactory.developmentModeDetector.env = this.builder.productionEnvironment;
            let serverResult = appServerFactory.createAppServer({
                onEvent: (event) => dispatchedEvents.push(event.eventType)
            });
            this.assert.strictEqual(serverResult.app, appServerFactory.app);
            this.assert.strictEqual(serverResult.appServer instanceof http.Server, true);
            this.assert.strictEqual(serverResult.http2CdnServer, false);
            this.assert.deepStrictEqual(dispatchedEvents, [
                'protocol-enforcement-enabled',
                'helmet-configured',
                'cors-configured',
                'http-server-created',
                'app-server-created'
            ]);
        });
    }

    async testTheCreateAppServerFailsWithAMissingCertificateKey()
    {
        await this.test('createAppServer returns false and sets the error when the https key file is missing', () => {
            let appServerFactory = new AppServerFactory();
            this.assert.strictEqual(
                appServerFactory.createAppServer({useHttps: true, keyPath: this.missingKeyPath}),
                false
            );
            this.assert.strictEqual(
                appServerFactory.error.message,
                'Could not read SSL key file: '+this.missingKeyPath
            );
        });
    }

    async testTheProductionResponseCarriesTheSecurityProtocolAndCorsHeaders()
    {
        await this.test('a production response carries the helmet, protocol and credentials CORS headers', async () => {
            let appServerFactory = this.builder.createFactory({});
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.playersPath, headers: {'Origin': this.clientOrigin}}
            );
            let cspDirectives = appServerFactory.securityConfigurer.helmetOptions.contentSecurityPolicy.directives;
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.deepStrictEqual(response.json, {players: this.builder.playerNames});
            this.assert.strictEqual(response.headers['x-forwarded-proto'], 'http');
            this.assert.strictEqual(response.headers['x-content-type-options'], 'nosniff');
            this.assert.strictEqual(
                response.headers['content-security-policy'].includes('default-src '+cspDirectives.defaultSrc.join(' ')),
                true
            );
            this.assert.strictEqual(response.headers['access-control-allow-origin'], this.clientOrigin);
            this.assert.strictEqual(response.headers['access-control-allow-credentials'], 'true');
            this.assert.strictEqual(Object.hasOwn(response.headers, 'origin-agent-cluster'), false);
        });
    }

    async testTheDevelopmentResponseRelaxesTheSecurityHeaders()
    {
        await this.test('a development response drops the CSP and HSTS and sets the origin agent cluster', async () => {
            let appServerFactory = this.builder.createFactory({developmentDomains: [this.developmentDomain]});
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.playersPath}
            );
            this.assert.strictEqual(appServerFactory.isDevelopmentMode, true);
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.strictEqual(response.headers['origin-agent-cluster'], '?0');
            this.assert.strictEqual(Object.hasOwn(response.headers, 'content-security-policy'), false);
            this.assert.strictEqual(Object.hasOwn(response.headers, 'strict-transport-security'), false);
        });
    }

    async testTheJsonAndUrlencodedBodiesAreParsed()
    {
        await this.test('the JSON and urlencoded request bodies are parsed', async () => {
            let appServerFactory = this.builder.createFactory({});
            let echoRequest = {path: this.builder.echoPath, method: 'POST'};
            let urlencodedHeaders = {'Content-Type': 'application/x-www-form-urlencoded'};
            await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
                let jsonResponse = await this.localHttpExchange.sendRequest(
                    port,
                    Object.assign({headers: this.jsonHeaders}, echoRequest),
                    FileHandler.readFile(this.builder.playerBodyPath)
                );
                let urlencodedResponse = await this.localHttpExchange.sendRequest(
                    port,
                    Object.assign({headers: urlencodedHeaders}, echoRequest),
                    this.urlencodedBody
                );
                this.assert.deepStrictEqual(jsonResponse.json, FileHandler.fetchFileJson(this.builder.playerBodyPath));
                this.assert.deepStrictEqual(urlencodedResponse.json, {name: 'Player', level: '3'});
            });
        });
    }

    async testTheJsonBodyIsNotSanitizedByDefault()
    {
        await this.test('the JSON request body reaches the routes untouched by default', async () => {
            let appServerFactory = this.builder.createFactory({});
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.echoPath, method: 'POST', headers: this.jsonHeaders},
                FileHandler.readFile(this.builder.xssBodyPath)
            );
            this.assert.deepStrictEqual(response.json, FileHandler.fetchFileJson(this.builder.xssBodyPath));
        });
    }

    async testTheJsonBodyIsSanitizedAgainstXss()
    {
        await this.test('the JSON request body strings are sanitized when the XSS protection is enabled', async () => {
            let appServerFactory = this.builder.createFactory({useXssProtection: true});
            let xssBody = FileHandler.fetchFileJson(this.builder.xssBodyPath);
            let sanitizedBody = {
                name: sanitizeHtml(xssBody.name, appServerFactory.sanitizeOptions),
                profile: {bio: sanitizeHtml(xssBody.profile.bio, appServerFactory.sanitizeOptions)}
            };
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.echoPath, method: 'POST', headers: this.jsonHeaders},
                FileHandler.readFile(this.builder.xssBodyPath)
            );
            this.assert.notDeepStrictEqual(sanitizedBody, xssBody);
            this.assert.deepStrictEqual(response.json, sanitizedBody);
        });
    }

    async testTheLargeResponsesAreGzipCompressed()
    {
        await this.test('the responses over the compression threshold are gzip compressed', async () => {
            let appServerFactory = this.builder.createFactory({});
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.largeContentPath, headers: {'Accept-Encoding': 'gzip'}}
            );
            this.assert.strictEqual(response.headers['content-encoding'], 'gzip');
            this.assert.strictEqual(String(zlib.gunzipSync(response.body)), this.builder.largeContent);
        });
    }

    async testTheNoCompressionHeaderSkipsTheCompression()
    {
        await this.test('the x-no-compression request header skips the compression', async () => {
            let appServerFactory = this.builder.createFactory({});
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.largeContentPath, headers: {'Accept-Encoding': 'gzip', 'X-No-Compression': '1'}}
            );
            this.assert.strictEqual(Object.hasOwn(response.headers, 'content-encoding'), false);
            this.assert.strictEqual(String(response.body), this.builder.largeContent);
        });
    }

    async testTheRequestLoggingCallbacksReceiveTheFinishedRequests()
    {
        await this.test('the request logging callbacks receive the successful and the failed requests', async () => {
            let successRequests = [];
            let errorRequests = [];
            let appServerFactory = this.builder.createFactory({
                onRequestSuccess: (requestData) => successRequests.push(requestData),
                onRequestError: (requestData) => errorRequests.push(requestData)
            });
            await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
                await this.localHttpExchange.sendRequest(port, {path: this.builder.playersPath});
                await this.localHttpExchange.sendRequest(port, {path: this.missingPath});
            });
            let successRequest = successRequests.shift();
            let errorRequest = errorRequests.shift();
            this.assert.strictEqual(successRequest.method, 'GET');
            this.assert.strictEqual(successRequest.path, this.builder.playersPath);
            this.assert.strictEqual(successRequest.statusCode, 200);
            this.assert.strictEqual(successRequest.ip, this.localHttpExchange.host);
            this.assert.strictEqual(errorRequest.path, this.missingPath);
            this.assert.strictEqual(errorRequest.statusCode, 404);
        });
    }

    async testTheStaticFilesAreServedWithTheCacheAndSecurityHeaders()
    {
        await this.test('the static files are served with the cache and security headers', async () => {
            let staticFile = await this.fetchStaticFile({});
            let serverHeaders = staticFile.serverHeaders;
            this.assert.strictEqual(staticFile.response.statusCode, 200);
            this.assert.strictEqual(
                String(staticFile.response.body),
                FileHandler.readFile(FileHandler.joinPaths(this.builder.testsPath, this.staticFileName))
            );
            this.assert.strictEqual(
                staticFile.response.headers['cache-control'],
                serverHeaders.buildCacheControlHeader(ServerDefaultConfigurations.cacheConfig['.js'])
            );
            this.assert.strictEqual(
                staticFile.response.headers['x-frame-options'],
                serverHeaders.expressSecurityHeaders['X-Frame-Options']
            );
            this.assert.strictEqual(staticFile.response.headers['vary'], serverHeaders.expressVaryHeader);
        });
    }

    async testTheDevelopmentStaticFilesAreNotCached()
    {
        await this.test('the development static files are served with the no cache headers', async () => {
            let staticFile = await this.fetchStaticFile({developmentDomains: [this.developmentDomain]});
            let serverHeaders = staticFile.serverHeaders;
            let responseHeaders = staticFile.response.headers;
            this.assert.strictEqual(staticFile.response.statusCode, 200);
            this.assert.strictEqual(responseHeaders['cache-control'], serverHeaders.expressCacheControlNoCache);
            this.assert.strictEqual(responseHeaders['pragma'], serverHeaders.expressPragma);
            this.assert.strictEqual(responseHeaders['expires'], serverHeaders.expressExpires);
        });
    }

    async testTheServeHomeReturnsTheHomepageAndRedirectsThePost()
    {
        await this.test('enableServeHome returns the homepage content and redirects the POST to it', async () => {
            let appServerFactory = this.builder.createFactory({});
            await appServerFactory.enableServeHome(appServerFactory.app, async () => this.homeContent);
            await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
                let homeResponse = await this.localHttpExchange.sendRequest(port, {path: '/'});
                let postResponse = await this.localHttpExchange.sendRequest(port, {path: '/', method: 'POST'});
                this.assert.strictEqual(homeResponse.statusCode, 200);
                this.assert.strictEqual(String(homeResponse.body), this.homeContent);
                this.assert.strictEqual(postResponse.statusCode, 302);
                this.assert.strictEqual(postResponse.headers['location'], '/');
            });
        });
    }

    async testTheServeHomeWithoutCallbackAnswersServerError()
    {
        await this.test('enableServeHome without a homepage callback answers 500 with the error message', async () => {
            let appServerFactory = this.builder.createFactory({});
            await appServerFactory.enableServeHome(appServerFactory.app);
            let response = await this.localHttpExchange.requestServer(appServerFactory.appServer, {path: '/'});
            this.assert.strictEqual(response.statusCode, 500);
            this.assert.strictEqual(String(response.body), 'Homepage contents could not be loaded.');
        });
    }

}

module.exports.TestAppServerFactory = TestAppServerFactory;
