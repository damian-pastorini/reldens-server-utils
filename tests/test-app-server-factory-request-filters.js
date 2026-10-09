/**
 *
 * Reldens - Server Utils - TestAppServerFactoryRequestFilters
 *
 */

const { BaseTest } = require('./base-test');
const { LocalHttpExchange } = require('./local-http-exchange');
const { AppServerFactoryTestBuilder } = require('./app-server-factory-test-builder');

class TestAppServerFactoryRequestFilters extends BaseTest
{

    constructor()
    {
        super();
        this.localHttpExchange = new LocalHttpExchange();
        this.builder = new AppServerFactoryTestBuilder();
        this.gameHostname = 'game.example.com';
        this.gameAliasHostname = 'www.game.example.com';
        this.unknownHostname = 'unknown.example.com';
        this.privateNetworkRange = '10.0.0.0/8';
        this.pathPrefix = '/api';
        this.allowedAddress = '203.0.113.9';
        this.deniedAddress = '198.51.100.7';
        this.globalRateLimitConfig = {globalRateLimit: 1, maxRequests: 1};
    }

    async runRefusedUpgradeAfterAProxiedRequest(ruleOverrides, appServerConfig, proxiedRequest, upgradeHeaders)
    {
        return await this.builder.runProxyExchange(ruleOverrides, appServerConfig, async (port) => ({
            proxiedStatusCode: (await this.localHttpExchange.sendRequest(port, proxiedRequest)).statusCode,
            upgradeStatusCode: await this.localHttpExchange.sendRefusedUpgrade(
                port,
                this.builder.websocketPath,
                upgradeHeaders
            ),
            targetUpgradesCount: this.builder.targetUpgradeRequests.length
        }));
    }

    assertRefusedUpgrade(exchange, upgradeStatusCode)
    {
        this.assert.strictEqual(exchange.proxiedStatusCode, 200);
        this.assert.strictEqual(exchange.upgradeStatusCode, upgradeStatusCode);
        this.assert.strictEqual(exchange.targetUpgradesCount, 0);
    }

    async testTheVirtualHostResolvesTheDomainAndItsAliases()
    {
        await this.test('the virtual hosts resolve the request domain by hostname and by alias', async () => {
            let appServerFactory = this.builder.createFactory({
                useVirtualHosts: true,
                domains: [{hostname: this.gameHostname, aliases: [this.gameAliasHostname]}]
            });
            await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
                let hostnameResponse = await this.localHttpExchange.sendRequest(
                    port,
                    {path: this.builder.domainPath, headers: {'Host': this.gameHostname}}
                );
                let aliasResponse = await this.localHttpExchange.sendRequest(
                    port,
                    {path: this.builder.domainPath, headers: {'Host': this.gameAliasHostname}}
                );
                this.assert.deepStrictEqual(hostnameResponse.json, {hostname: this.gameHostname});
                this.assert.deepStrictEqual(aliasResponse.json, {hostname: this.gameHostname});
            });
        });
    }

    async testTheUnknownVirtualHostGetsNotFoundAndCallsOnError()
    {
        await this.test('an unknown virtual host gets 404 and is reported to the onError callback', async () => {
            let reportedErrors = [];
            let appServerFactory = this.builder.createFactory({
                useVirtualHosts: true,
                domains: [{hostname: this.gameHostname}],
                onError: (errorData) => reportedErrors.push(errorData)
            });
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.domainPath, headers: {'Host': this.unknownHostname}}
            );
            let reportedError = reportedErrors.shift();
            this.assert.strictEqual(response.statusCode, 404);
            this.assert.strictEqual(String(response.body), 'Domain not found');
            this.assert.strictEqual(reportedError.key, 'virtual-host-unknown-domain');
            this.assert.strictEqual(reportedError.hostname, this.unknownHostname);
        });
    }

    async testTheDeniedAddressIsForbidden()
    {
        await this.test('a request from a denied address gets 403 with the forbidden message', async () => {
            let appServerFactory = this.builder.createFactory({
                ipLists: {enabled: true, allow: [], deny: [this.localHttpExchange.host]}
            });
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.playersPath}
            );
            this.assert.strictEqual(response.statusCode, 403);
            this.assert.strictEqual(String(response.body), appServerFactory.ipListsConfigurer.forbiddenMessage);
        });
    }

    async testTheAddressOutsideTheDenyListIsServed()
    {
        await this.test('a request from an address outside the deny list is served', async () => {
            let appServerFactory = this.builder.createFactory({
                ipLists: {enabled: true, allow: [], deny: [this.privateNetworkRange]}
            });
            let response = await this.localHttpExchange.requestServer(
                appServerFactory.appServer,
                {path: this.builder.playersPath}
            );
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.deepStrictEqual(response.json, {players: this.builder.playerNames});
        });
    }

    async testTheGlobalRateLimitRejectsTheRequestsOverTheLimit()
    {
        await this.test('the global rate limit answers 429 with the message after the max requests', async () => {
            let appServerFactory = this.builder.createFactory({globalRateLimit: 1, maxRequests: 2});
            let responses = [];
            await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
                for(let requestNumber = 0; requestNumber <= appServerFactory.maxRequests; requestNumber++){
                    responses.push(await this.localHttpExchange.sendRequest(port, {path: this.builder.playersPath}));
                }
            });
            this.assert.deepStrictEqual(responses.map((response) => response.statusCode), [200, 200, 429]);
            this.assert.strictEqual(String(responses.pop().body), appServerFactory.tooManyRequestsMessage);
        });
    }

    async testTheProtocolHeaderIgnoresTheVisitorForwardedProto()
    {
        await this.test('the X-Forwarded-Proto response header is the request protocol, not the visitor value', async () => {
            let response = await this.localHttpExchange.requestServer(
                this.builder.createFactory({}).appServer,
                {path: this.builder.playersPath, headers: {'X-Forwarded-Proto': 'https'}}
            );
            this.assert.strictEqual(response.headers['x-forwarded-proto'], 'http');
        });
    }

    async testTheProxiedUpgradeForAnotherHostnameIsRefused()
    {
        await this.test('a websocket upgrade for another hostname is refused and never reaches the target', async () => {
            let exchange = await this.runRefusedUpgradeAfterAProxiedRequest(
                {},
                {},
                this.builder.proxiedRequest,
                this.builder.otherHostRequest.headers
            );
            this.assertRefusedUpgrade(exchange, 404);
        });
    }

    async testTheProxiedUpgradeOutsideThePathPrefixIsRefused()
    {
        await this.test('a websocket upgrade outside the rule path prefix is refused', async () => {
            let exchange = await this.runRefusedUpgradeAfterAProxiedRequest(
                {pathPrefix: this.pathPrefix},
                {},
                Object.assign({}, this.builder.proxiedRequest, {path: this.pathPrefix+this.builder.proxiedPath}),
                this.builder.proxiedRequest.headers
            );
            this.assertRefusedUpgrade(exchange, 404);
        });
    }

    async testTheProxiedUpgradeFromADeniedAddressIsRefused()
    {
        await this.test('a websocket upgrade from a denied address is refused and never reaches the target', async () => {
            let exchange = await this.runRefusedUpgradeAfterAProxiedRequest(
                {},
                {trustedProxy: 'loopback', ipLists: {enabled: true, deny: [this.deniedAddress]}},
                {
                    path: this.builder.proxiedPath,
                    headers: Object.assign({'X-Forwarded-For': this.allowedAddress}, this.builder.proxiedRequest.headers)
                },
                Object.assign({'X-Forwarded-For': this.deniedAddress}, this.builder.proxiedRequest.headers)
            );
            this.assertRefusedUpgrade(exchange, 403);
        });
    }

    async testTheProxiedRequestsCountForTheGlobalRateLimit()
    {
        await this.test('the proxied requests over the global rate limit get 429', async () => {
            let statusCodes = await this.builder.runProxyExchange({}, this.globalRateLimitConfig, async (port) => [
                (await this.localHttpExchange.sendRequest(port, this.builder.proxiedRequest)).statusCode,
                (await this.localHttpExchange.sendRequest(port, this.builder.proxiedRequest)).statusCode
            ]);
            this.assert.deepStrictEqual(statusCodes, [200, 429]);
        });
    }

    async testTheProxiedUpgradeOverTheGlobalRateLimitIsRefused()
    {
        await this.test('a websocket upgrade over the global rate limit is refused and never reaches the target', async () => {
            let exchange = await this.runRefusedUpgradeAfterAProxiedRequest(
                {},
                this.globalRateLimitConfig,
                this.builder.proxiedRequest,
                this.builder.proxiedRequest.headers
            );
            this.assertRefusedUpgrade(exchange, 429);
        });
    }

}

module.exports.TestAppServerFactoryRequestFilters = TestAppServerFactoryRequestFilters;
