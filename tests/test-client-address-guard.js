/**
 *
 * Reldens - Server Utils - TestClientAddressGuard
 *
 */

const { EventEmitter } = require('events');
const { BaseTest } = require('./base-test');
const proxyaddr = require('proxy-addr');
const { AppServerFactory } = require('../lib/app-server-factory');
const { Http2CdnServer } = require('../lib/http2-cdn-server');

class TestClientAddressGuard extends BaseTest
{

    constructor()
    {
        super();
        this.peerAddress = '198.51.100.7';
        this.proxyAddress = '127.0.0.1';
        this.spoofedHeaders = {
            'x-real-ip': '203.0.113.1',
            'x-forwarded-for': '203.0.113.2',
            'x-client-ip': '203.0.113.3'
        };
        this.matchmakeUrl = '/matchmake/joinOrCreate/room_game';
    }

    createGuardedServer(trustedProxy, deny)
    {
        let appServerFactory = new AppServerFactory();
        appServerFactory.trustedProxy = trustedProxy;
        appServerFactory.setupTrustedProxy();
        appServerFactory.ipListsConfigurer.setLists({enabled: true, allow: [], deny});
        let guardedServer = {server: new EventEmitter(), receivedRequests: []};
        guardedServer.server.on('request', (request) => guardedServer.receivedRequests.push(request));
        guardedServer.server.on('upgrade', (request) => guardedServer.receivedRequests.push(request));
        appServerFactory.attachClientAddressGuard(guardedServer.server);
        return guardedServer;
    }

    emitRequest(guardedServer, eventName, url, peerAddress)
    {
        let response = {statusCode: 200, body: ''};
        response.end = (body) => {
            response.body = body;
        };
        guardedServer.server.emit(
            eventName,
            {url, headers: Object.assign({}, this.spoofedHeaders), socket: {remoteAddress: peerAddress}},
            response
        );
        return response;
    }

    async testTheSpoofedUpgradeHeadersAreReplacedByThePeerAddress()
    {
        await this.test('the forwarding headers of an upgrade are replaced by the peer address', () => {
            let guardedServer = this.createGuardedServer('', []);
            this.emitRequest(guardedServer, 'upgrade', '/', this.peerAddress);
            this.assert.deepStrictEqual(guardedServer.receivedRequests.pop().headers, {'x-real-ip': this.peerAddress});
        });
    }

    async testTheTrustedLoopbackProxyKeepsTheForwardedAddress()
    {
        await this.test('a trusted loopback proxy keeps the forwarded client address on an upgrade', () => {
            let guardedServer = this.createGuardedServer('loopback', []);
            this.emitRequest(guardedServer, 'upgrade', '/', this.proxyAddress);
            this.assert.deepStrictEqual(
                guardedServer.receivedRequests.pop().headers,
                {'x-real-ip': this.spoofedHeaders['x-forwarded-for']}
            );
        });
    }

    async testTheDeniedPeerGetsForbiddenOnMatchmake()
    {
        await this.test('a denied peer with a spoofed X-Real-IP gets 403 on matchmake and skips the listeners', () => {
            let guardedServer = this.createGuardedServer('', [this.peerAddress]);
            let response = this.emitRequest(guardedServer, 'request', this.matchmakeUrl, this.peerAddress);
            this.assert.strictEqual(response.statusCode, 403);
            this.assert.strictEqual(response.body, 'Forbidden.');
            this.assert.strictEqual(guardedServer.receivedRequests.length, 0);
        });
    }

    async testTheAllowedMatchmakeRequestReachesTheListenersWithThePeerAddress()
    {
        await this.test('an allowed matchmake request reaches the listeners with only the peer address header', () => {
            let guardedServer = this.createGuardedServer('', [this.spoofedHeaders['x-real-ip']]);
            let response = this.emitRequest(guardedServer, 'request', this.matchmakeUrl, this.peerAddress);
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.deepStrictEqual(guardedServer.receivedRequests.pop().headers, {'x-real-ip': this.peerAddress});
        });
    }

    async testTheOtherRequestsReachTheListenersUntouched()
    {
        await this.test('the requests outside matchmake reach the listeners with their headers untouched', () => {
            let guardedServer = this.createGuardedServer('', [this.peerAddress]);
            let response = this.emitRequest(guardedServer, 'request', '/game/', this.peerAddress);
            this.assert.strictEqual(response.statusCode, 200);
            this.assert.deepStrictEqual(guardedServer.receivedRequests.pop().headers, this.spoofedHeaders);
        });
    }

    async testTheCdnRequestOriginIgnoresTheVisitorForwardingHeaders()
    {
        await this.test('the CDN request origin uses the peer address and Host for a peer that is not trusted', () => {
            let headers = Object.assign({host: 'cdn.example.com', 'x-forwarded-host': 'other.example.com'}, this.spoofedHeaders);
            this.assert.deepStrictEqual(
                new Http2CdnServer().resolveRequestOrigin(headers, {remoteAddress: this.peerAddress}, 'host'),
                {hostname: 'cdn.example.com', ip: this.peerAddress}
            );
        });
    }

    async testTheCdnRequestOriginKeepsTheTrustedProxyValues()
    {
        await this.test('the CDN request origin uses the forwarded address and host of a trusted proxy', () => {
            let headers = Object.assign({host: 'cdn.example.com', 'x-forwarded-host': 'other.example.com'}, this.spoofedHeaders);
            let cdnServer = new Http2CdnServer();
            cdnServer.trustProxyFunction = proxyaddr.compile('loopback');
            this.assert.deepStrictEqual(
                cdnServer.resolveRequestOrigin(headers, {remoteAddress: this.proxyAddress}, 'host'),
                {hostname: 'other.example.com', ip: this.spoofedHeaders['x-forwarded-for']}
            );
        });
    }

}

module.exports.TestClientAddressGuard = TestClientAddressGuard;
