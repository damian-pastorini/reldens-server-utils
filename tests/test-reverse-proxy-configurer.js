/**
 *
 * Reldens - Server Utils - TestReverseProxyConfigurer
 *
 */

const { BaseTest } = require('./base-test');
const { LocalHttpExchange } = require('./local-http-exchange');
const { AppServerFactoryTestBuilder } = require('./app-server-factory-test-builder');
const { FileHandler } = require('../lib/file-handler');

class TestReverseProxyConfigurer extends BaseTest
{

    constructor()
    {
        super();
        this.localHttpExchange = new LocalHttpExchange();
        this.builder = new AppServerFactoryTestBuilder();
        this.pathPrefix = '/api';
        this.websocketMessage = 'ping';
        this.visitorForwardingHeaders = {
            'X-Forwarded-For': '203.0.113.9',
            'X-Real-IP': '203.0.113.10',
            'X-Client-IP': '203.0.113.11',
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Host': 'public.example.com'
        };
        this.visitorRequest = {
            path: this.builder.proxiedPath,
            headers: Object.assign({'Host': this.builder.proxiedHostname}, this.visitorForwardingHeaders)
        };
    }

    assertProxyForwardedHeaders(targetHeaders)
    {
        this.assert.strictEqual(targetHeaders['x-forwarded-for'], this.localHttpExchange.host);
        this.assert.strictEqual(targetHeaders['x-real-ip'], this.localHttpExchange.host);
        this.assert.strictEqual(targetHeaders['x-forwarded-proto'], 'http');
        this.assert.strictEqual(targetHeaders['x-forwarded-host'], this.builder.proxiedHostname);
        this.assert.strictEqual(Object.hasOwn(targetHeaders, 'x-client-ip'), false);
    }

    async testTheRuleHostnameIsForwardedToTheTarget()
    {
        await this.test('a rule hostname request reaches the target with its path, query and target host', async () => {
            let exchange = await this.builder.runProxyExchange({}, {}, async (port, targetPort) => ({
                targetHost: this.localHttpExchange.host+':'+targetPort,
                response: await this.localHttpExchange.sendRequest(port, this.builder.proxiedRequest)
            }));
            this.assert.strictEqual(exchange.response.statusCode, 200);
            this.assert.strictEqual(exchange.response.json.method, 'GET');
            this.assert.strictEqual(exchange.response.json.url, this.builder.proxiedPath);
            this.assert.strictEqual(exchange.response.json.headers.host, exchange.targetHost);
        });
    }

    async testTheOtherHostnamesReachTheLocalRoutes()
    {
        await this.test('the requests for other hostnames skip the proxy and reach the local routes', async () => {
            let response = await this.builder.runProxyExchange(
                {},
                {},
                (port) => this.localHttpExchange.sendRequest(port, this.builder.otherHostRequest)
            );
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.deepStrictEqual(response.json, {players: this.builder.playerNames});
        });
    }

    async testTheDirectModeForwardsEveryHostname()
    {
        await this.test('without virtual hosts the requests for any hostname are forwarded', async () => {
            let response = await this.builder.runProxyExchange(
                {},
                {useVirtualHosts: false},
                (port) => this.localHttpExchange.sendRequest(port, this.builder.otherHostRequest)
            );
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.strictEqual(response.json.url, this.builder.proxiedPath);
        });
    }

    async testThePathPrefixIsRemovedBeforeForwarding()
    {
        await this.test('the rule path prefix is removed from the path forwarded to the target', async () => {
            let response = await this.builder.runProxyExchange(
                {pathPrefix: this.pathPrefix},
                {},
                (port) => this.localHttpExchange.sendRequest(
                    port,
                    Object.assign({}, this.builder.proxiedRequest, {path: this.pathPrefix+this.builder.proxiedPath})
                )
            );
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.strictEqual(response.json.url, this.builder.proxiedPath);
        });
    }

    async testTheRequestBodyIsStreamedToTheTarget()
    {
        await this.test('the POST request body and content type reach the target untouched', async () => {
            let requestBody = FileHandler.readFile(this.builder.playerBodyPath);
            let jsonContentType = this.localHttpExchange.jsonContentType;
            let response = await this.builder.runProxyExchange({}, {}, (port) => this.localHttpExchange.sendRequest(
                port,
                {
                    path: this.builder.proxiedPath,
                    method: 'POST',
                    headers: {'Host': this.builder.proxiedHostname, 'Content-Type': jsonContentType}
                },
                requestBody
            ));
            this.assert.strictEqual(response.json.method, 'POST');
            this.assert.strictEqual(response.json.body, requestBody);
            this.assert.strictEqual(response.json.headers['content-type'], jsonContentType);
        });
    }

    async testTheWebsocketUpgradeIsTunneledToTheTarget()
    {
        await this.test('a websocket upgrade for the rule hostname is tunneled to the target', async () => {
            let exchange = await this.builder.runProxyExchange({}, {}, async (port) => {
                let upgrade = await this.localHttpExchange.sendUpgrade(
                    port,
                    this.builder.websocketPath,
                    this.builder.proxiedRequest.headers
                );
                let reply = await this.localHttpExchange.exchangeSocketMessage(upgrade.socket, this.websocketMessage);
                upgrade.socket.destroy();
                return {statusCode: upgrade.statusCode, reply};
            });
            this.assert.strictEqual(exchange.statusCode, 101);
            this.assert.strictEqual(exchange.reply, this.builder.echoPrefix+this.websocketMessage);
        });
    }

    async testTheConfiguredEventIsDispatched()
    {
        await this.test('the reverse proxy configured event is dispatched with the rules data', async () => {
            let dispatchedEvents = [];
            this.builder.createProxyFactory(
                await this.localHttpExchange.findUnusedPort(),
                {},
                {onEvent: (event) => dispatchedEvents.push(event)}
            );
            let proxyEvent = dispatchedEvents.filter((event) => 'reverse-proxy-configured' === event.eventType).shift();
            this.assert.deepStrictEqual(proxyEvent.data, {rulesCount: 1, useVirtualHosts: true});
        });
    }

    async testTheProxySendsItsOwnForwardingHeaders()
    {
        await this.test('the proxy sends its own client address, protocol and host to the target', async () => {
            let response = await this.builder.runProxyExchange(
                {},
                {},
                (port) => this.localHttpExchange.sendRequest(port, this.builder.proxiedRequest)
            );
            this.assertProxyForwardedHeaders(response.json.headers);
        });
    }

    async testTheVisitorForwardingHeadersAreReplaced()
    {
        await this.test('the forwarding headers sent by a visitor are replaced by the proxy values', async () => {
            let response = await this.builder.runProxyExchange(
                {},
                {},
                (port) => this.localHttpExchange.sendRequest(port, this.visitorRequest)
            );
            this.assertProxyForwardedHeaders(response.json.headers);
        });
    }

    async testTheVisitorForwardingHeadersAreReplacedWithAnExpectHeader()
    {
        await this.test('the visitor forwarding headers are replaced on a request with an Expect header', async () => {
            let response = await this.builder.runProxyExchange({}, {}, (port) => this.localHttpExchange.sendRequest(
                port,
                {
                    path: this.visitorRequest.path,
                    headers: Object.assign({'Expect': '100-continue'}, this.visitorRequest.headers)
                }
            ));
            this.assertProxyForwardedHeaders(response.json.headers);
        });
    }

    async testTheTrustedUpstreamForwardingHeadersAreKept()
    {
        await this.test('the forwarding headers of a trusted upstream proxy reach the target', async () => {
            let response = await this.builder.runProxyExchange(
                {},
                {trustedProxy: 'loopback'},
                (port) => this.localHttpExchange.sendRequest(port, this.visitorRequest)
            );
            let targetHeaders = response.json.headers;
            let upstreamHeaders = this.visitorForwardingHeaders;
            this.assert.strictEqual(targetHeaders['x-forwarded-for'], upstreamHeaders['X-Forwarded-For']);
            this.assert.strictEqual(targetHeaders['x-real-ip'], upstreamHeaders['X-Forwarded-For']);
            this.assert.strictEqual(targetHeaders['x-forwarded-proto'], upstreamHeaders['X-Forwarded-Proto']);
            this.assert.strictEqual(targetHeaders['x-forwarded-host'], upstreamHeaders['X-Forwarded-Host']);
            this.assert.strictEqual(Object.hasOwn(targetHeaders, 'x-client-ip'), false);
        });
    }

    async testTheVisitorForwardingHeadersOfAnUpgradeAreReplaced()
    {
        await this.test('the forwarding headers sent by a visitor on a websocket upgrade are replaced', async () => {
            let upgradeHeaders = await this.builder.runProxyExchange({}, {}, async (port) => {
                let upgrade = await this.localHttpExchange.sendUpgrade(
                    port,
                    this.builder.websocketPath,
                    this.visitorRequest.headers
                );
                upgrade.socket.destroy();
                return this.builder.targetUpgradeRequests.pop().headers;
            });
            this.assertProxyForwardedHeaders(upgradeHeaders);
        });
    }

    async testTheUnavailableTargetAnswersBadGatewayAndCallsOnError()
    {
        await this.test('an unavailable target answers 502, closes the upgrade and reports both to onError', async () => {
            let reportedErrors = [];
            let appServerFactory = this.builder.createProxyFactory(
                await this.localHttpExchange.findUnusedPort(),
                {},
                {onError: (errorData) => reportedErrors.push(errorData)}
            );
            let response = await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
                let proxiedResponse = await this.localHttpExchange.sendRequest(port, this.builder.proxiedRequest);
                await this.assert.rejects(
                    this.localHttpExchange.sendUpgrade(
                        port,
                        this.builder.websocketPath,
                        this.builder.proxiedRequest.headers
                    )
                );
                return proxiedResponse;
            });
            this.assert.strictEqual(response.statusCode, 502);
            this.assert.strictEqual(String(response.body), 'Bad Gateway - Backend server unavailable');
            this.assert.deepStrictEqual(reportedErrors.map((errorData) => errorData.key), ['proxy-error', 'proxy-error']);
            this.assert.deepStrictEqual(
                reportedErrors.map((errorData) => errorData.hostname),
                [this.builder.proxiedHostname, this.builder.proxiedHostname]
            );
        });
    }

}

module.exports.TestReverseProxyConfigurer = TestReverseProxyConfigurer;
