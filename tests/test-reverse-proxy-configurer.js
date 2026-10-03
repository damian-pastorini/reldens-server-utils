/**
 *
 * Reldens - Server Utils - TestReverseProxyConfigurer
 *
 */

const http = require('http');
const express = require('express');
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
        this.proxiedHostname = 'game.example.com';
        this.otherHostname = 'other.example.com';
        this.proxiedPath = this.builder.playersPath+'?page=2';
        this.proxiedRequest = {path: this.proxiedPath, headers: {'Host': this.proxiedHostname}};
        this.otherHostRequest = {path: this.proxiedPath, headers: {'Host': this.otherHostname}};
        this.pathPrefix = '/api';
        this.websocketPath = '/ws';
        this.websocketMessage = 'ping';
        this.echoPrefix = 'echo:';
        this.switchingProtocolsResponse = 'HTTP/1.1 101 Switching Protocols\r\n'
            +'Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n';
    }

    createTargetServer()
    {
        let targetApp = express();
        targetApp.use(express.text({type: () => true}));
        targetApp.use((req, res) => res.json({method: req.method, url: req.url, headers: req.headers, body: req.body}));
        let targetServer = http.createServer(targetApp);
        targetServer.on('upgrade', (req, socket) => {
            socket.on('data', (message) => socket.write(this.echoPrefix+String(message)));
            socket.on('end', () => socket.end());
            socket.write(this.switchingProtocolsResponse);
        });
        return targetServer;
    }

    createProxyFactory(targetPort, ruleOverrides, appServerConfig)
    {
        let proxyConfig = {
            reverseProxyEnabled: true,
            useVirtualHosts: true,
            reverseProxyRules: [Object.assign(
                {hostname: this.proxiedHostname, target: 'http://'+this.localHttpExchange.host+':'+targetPort},
                ruleOverrides
            )]
        };
        Object.assign(proxyConfig, appServerConfig);
        return this.builder.createFactory(proxyConfig);
    }

    async runProxyExchange(ruleOverrides, appServerConfig, exchangeCallback)
    {
        let targetServer = this.createTargetServer();
        let targetPort = await this.localHttpExchange.startServer(targetServer);
        try {
            return await this.localHttpExchange.runWithServer(
                this.createProxyFactory(targetPort, ruleOverrides, appServerConfig).appServer,
                (port) => exchangeCallback(port, targetPort)
            );
        } finally {
            await this.localHttpExchange.stopServer(targetServer);
        }
    }

    async testTheRuleHostnameIsForwardedToTheTarget()
    {
        await this.test('a rule hostname request reaches the target with its path, query and target host', async () => {
            let exchange = await this.runProxyExchange({}, {}, async (port, targetPort) => ({
                targetHost: this.localHttpExchange.host+':'+targetPort,
                response: await this.localHttpExchange.sendRequest(port, this.proxiedRequest)
            }));
            this.assert.strictEqual(exchange.response.statusCode, 200);
            this.assert.strictEqual(exchange.response.json.method, 'GET');
            this.assert.strictEqual(exchange.response.json.url, this.proxiedPath);
            this.assert.strictEqual(exchange.response.json.headers.host, exchange.targetHost);
        });
    }

    async testTheOtherHostnamesReachTheLocalRoutes()
    {
        await this.test('the requests for other hostnames skip the proxy and reach the local routes', async () => {
            let response = await this.runProxyExchange(
                {},
                {},
                (port) => this.localHttpExchange.sendRequest(port, this.otherHostRequest)
            );
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.deepStrictEqual(response.json, {players: this.builder.playerNames});
        });
    }

    async testTheDirectModeForwardsEveryHostname()
    {
        await this.test('without virtual hosts the requests for any hostname are forwarded', async () => {
            let response = await this.runProxyExchange(
                {},
                {useVirtualHosts: false},
                (port) => this.localHttpExchange.sendRequest(port, this.otherHostRequest)
            );
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.strictEqual(response.json.url, this.proxiedPath);
        });
    }

    async testThePathPrefixIsRemovedBeforeForwarding()
    {
        await this.test('the rule path prefix is removed from the path forwarded to the target', async () => {
            let response = await this.runProxyExchange(
                {pathPrefix: this.pathPrefix},
                {},
                (port) => this.localHttpExchange.sendRequest(
                    port,
                    Object.assign({}, this.proxiedRequest, {path: this.pathPrefix+this.proxiedPath})
                )
            );
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.strictEqual(response.json.url, this.proxiedPath);
        });
    }

    async testTheRequestBodyIsStreamedToTheTarget()
    {
        await this.test('the POST request body and content type reach the target untouched', async () => {
            let requestBody = FileHandler.readFile(this.builder.playerBodyPath);
            let jsonContentType = this.localHttpExchange.jsonContentType;
            let response = await this.runProxyExchange({}, {}, (port) => this.localHttpExchange.sendRequest(
                port,
                {
                    path: this.proxiedPath,
                    method: 'POST',
                    headers: {'Host': this.proxiedHostname, 'Content-Type': jsonContentType}
                },
                requestBody
            ));
            this.assert.strictEqual(response.json.method, 'POST');
            this.assert.strictEqual(response.json.body, requestBody);
            this.assert.strictEqual(response.json.headers['content-type'], jsonContentType);
        });
    }

    async testTheWebsocketUpgradeIsTunneledAfterTheFirstProxiedRequest()
    {
        await this.test('a websocket upgrade is tunneled to the target after the first proxied request', async () => {
            let exchange = await this.runProxyExchange({}, {}, async (port) => {
                await this.localHttpExchange.sendRequest(port, this.proxiedRequest);
                let upgrade = await this.localHttpExchange.sendUpgrade(
                    port,
                    this.websocketPath,
                    this.proxiedRequest.headers
                );
                let reply = await this.localHttpExchange.exchangeSocketMessage(upgrade.socket, this.websocketMessage);
                upgrade.socket.destroy();
                return {statusCode: upgrade.statusCode, reply};
            });
            this.assert.strictEqual(exchange.statusCode, 101);
            this.assert.strictEqual(exchange.reply, this.echoPrefix+this.websocketMessage);
        });
    }

    async testTheConfiguredEventIsDispatched()
    {
        await this.test('the reverse proxy configured event is dispatched with the rules data', async () => {
            let dispatchedEvents = [];
            this.createProxyFactory(
                await this.localHttpExchange.findUnusedPort(),
                {},
                {onEvent: (event) => dispatchedEvents.push(event)}
            );
            let proxyEvent = dispatchedEvents.filter((event) => 'reverse-proxy-configured' === event.eventType).shift();
            this.assert.deepStrictEqual(proxyEvent.data, {rulesCount: 1, useVirtualHosts: true});
        });
    }

    async testTheForwardedHeadersAreSentToTheTarget()
    {
        await this.test('the X-Forwarded-For, Proto and Host headers are sent to the target', async () => {
            let response = await this.runProxyExchange(
                {},
                {},
                (port) => this.localHttpExchange.sendRequest(port, this.proxiedRequest)
            );
            this.assert.strictEqual(response.json.headers['x-forwarded-for'], this.localHttpExchange.host);
            this.assert.strictEqual(response.json.headers['x-forwarded-proto'], 'http');
            this.assert.strictEqual(response.json.headers['x-forwarded-host'], this.proxiedHostname);
        });
    }

    async testTheUnavailableTargetAnswersBadGatewayAndCallsOnError()
    {
        await this.test('an unavailable target answers 502, closes the upgrade and reports both to onError', async () => {
            let reportedErrors = [];
            let appServerFactory = this.createProxyFactory(
                await this.localHttpExchange.findUnusedPort(),
                {},
                {onError: (errorData) => reportedErrors.push(errorData)}
            );
            let response = await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
                let proxiedResponse = await this.localHttpExchange.sendRequest(port, this.proxiedRequest);
                await this.assert.rejects(
                    this.localHttpExchange.sendUpgrade(port, this.websocketPath, this.proxiedRequest.headers)
                );
                return proxiedResponse;
            });
            this.assert.strictEqual(response.statusCode, 502);
            this.assert.strictEqual(String(response.body), 'Bad Gateway - Backend server unavailable');
            this.assert.deepStrictEqual(reportedErrors.map((errorData) => errorData.key), ['proxy-error', 'proxy-error']);
            this.assert.deepStrictEqual(
                reportedErrors.map((errorData) => errorData.hostname),
                [this.proxiedHostname, this.proxiedHostname]
            );
        });
    }

}

module.exports.TestReverseProxyConfigurer = TestReverseProxyConfigurer;
