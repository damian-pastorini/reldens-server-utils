/**
 *
 * Reldens - Server Utils - TestExpressModuleReexports
 *
 */

const { BaseTest } = require('./base-test');
const { ExpressSession, ExpressBasicAuth } = require('../index');

class TestExpressModuleReexports extends BaseTest
{

    async testTheExpressSessionExportIsTheExpressSessionModule()
    {
        await this.test('ExpressSession is the express-session module with its Store class', () => {
            this.assert.strictEqual(ExpressSession, require('express-session'));
            this.assert.strictEqual('function', typeof ExpressSession.Store);
        });
    }

    async testTheExpressBasicAuthExportIsTheExpressBasicAuthModule()
    {
        await this.test('ExpressBasicAuth is the express-basic-auth middleware factory', () => {
            this.assert.strictEqual(ExpressBasicAuth, require('express-basic-auth'));
            this.assert.strictEqual('function', typeof ExpressBasicAuth({users: {admin: 'test'}}));
        });
    }

}

module.exports.TestExpressModuleReexports = TestExpressModuleReexports;
