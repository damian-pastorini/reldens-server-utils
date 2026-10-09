/**
 *
 * Reldens - Server Utils - AppServerFactoryTestBuilder
 *
 */

const http = require('http');
const express = require('express');
const { LocalHttpExchange } = require('./local-http-exchange');
const { AppServerFactory } = require('../lib/app-server-factory');
const { FileHandler } = require('../lib/file-handler');

class AppServerFactoryTestBuilder
{

    constructor()
    {
        this.localHttpExchange = new LocalHttpExchange();
        this.productionEnvironment = 'production';
        this.testsPath = FileHandler.joinPaths(process.cwd(), 'tests');
        this.fixturesPath = FileHandler.joinPaths(this.testsPath, 'fixtures');
        this.playerBodyPath = FileHandler.joinPaths(this.fixturesPath, 'player-request-body.json');
        this.xssBodyPath = FileHandler.joinPaths(this.fixturesPath, 'xss-request-body.json');
        this.playersPath = '/players';
        this.largeContentPath = '/large-content';
        this.echoPath = '/echo';
        this.domainPath = '/domain';
        this.playerNames = ['Player1', 'Player2'];
        this.largeContent = 'a'.repeat(new AppServerFactory().compressionOptions.threshold + 1);
        this.proxiedHostname = 'game.example.com';
        this.otherHostname = 'other.example.com';
        this.proxiedPath = this.playersPath+'?page=2';
        this.proxiedRequest = {path: this.proxiedPath, headers: {'Host': this.proxiedHostname}};
        this.otherHostRequest = {path: this.proxiedPath, headers: {'Host': this.otherHostname}};
        this.websocketPath = '/ws';
        this.echoPrefix = 'echo:';
        this.switchingProtocolsResponse = 'HTTP/1.1 101 Switching Protocols\r\n'
            +'Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n';
        this.targetUpgradeRequests = [];
    }

    createFactory(appServerConfig)
    {
        let appServerFactory = new AppServerFactory();
        appServerFactory.developmentModeDetector.env = this.productionEnvironment;
        appServerFactory.createAppServer(appServerConfig);
        appServerFactory.app.get(this.playersPath, (req, res) => res.json({players: this.playerNames}));
        appServerFactory.app.get(this.largeContentPath, (req, res) => res.send(this.largeContent));
        appServerFactory.app.post(this.echoPath, (req, res) => res.json(req.body));
        appServerFactory.app.get(this.domainPath, (req, res) => res.json({hostname: req.domain.hostname}));
        return appServerFactory;
    }

    createTargetServer()
    {
        this.targetUpgradeRequests = [];
        let targetApp = express();
        targetApp.use(express.text({type: () => true}));
        targetApp.use((req, res) => res.json({method: req.method, url: req.url, headers: req.headers, body: req.body}));
        let targetServer = http.createServer(targetApp);
        targetServer.on('upgrade', (req, socket) => {
            this.targetUpgradeRequests.push(req);
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
        return this.createFactory(proxyConfig);
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

}

module.exports.AppServerFactoryTestBuilder = AppServerFactoryTestBuilder;
