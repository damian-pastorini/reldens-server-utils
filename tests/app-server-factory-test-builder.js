/**
 *
 * Reldens - Server Utils - AppServerFactoryTestBuilder
 *
 */

const { AppServerFactory } = require('../lib/app-server-factory');
const { FileHandler } = require('../lib/file-handler');

class AppServerFactoryTestBuilder
{

    constructor()
    {
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

}

module.exports.AppServerFactoryTestBuilder = AppServerFactoryTestBuilder;
