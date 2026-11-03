/**
 *
 * Reldens - Server Utils - TestAppServerFactoryStatics
 *
 */

const express = require('express');
const { BaseTest } = require('./base-test');
const { LocalHttpExchange } = require('./local-http-exchange');
const { AppServerFactoryTestBuilder } = require('./app-server-factory-test-builder');
const { AppServerFactory } = require('../lib/app-server-factory');
const { FileHandler } = require('../lib/file-handler');

class TestAppServerFactoryStatics extends BaseTest
{

    constructor()
    {
        super();
        this.localHttpExchange = new LocalHttpExchange();
        this.builder = new AppServerFactoryTestBuilder();
        this.staticsPath = '/assets';
        this.publicFixturePath = this.staticsPath+'/'+FileHandler.getFileName(this.builder.playerBodyPath);
        this.privateFixturePath = this.staticsPath+'/.private-data/private-file.txt';
    }

    async assertFixtureStatics(appServerFactory, privateStatusCode)
    {
        let fixtureStatics = await this.localHttpExchange.runWithServer(appServerFactory.appServer, async (port) => {
            return {
                publicResponse: await this.localHttpExchange.sendRequest(port, {path: this.publicFixturePath}),
                privateResponse: await this.localHttpExchange.sendRequest(port, {path: this.privateFixturePath})
            };
        });
        this.assert.strictEqual(
            String(fixtureStatics.publicResponse.body),
            FileHandler.readFile(this.builder.playerBodyPath)
        );
        this.assert.strictEqual(fixtureStatics.privateResponse.statusCode, privateStatusCode);
    }

    async testTheServedStaticsIgnoreTheFilesInsideDotFolders()
    {
        await this.test('serveStaticsPath serves the files and answers 404 for the files inside a dot folder', async () => {
            let appServerFactory = this.builder.createFactory({});
            await appServerFactory.serveStaticsPath(appServerFactory.app, this.staticsPath, this.builder.fixturesPath);
            await this.assertFixtureStatics(appServerFactory, 404);
        });
    }

    async testTheApplicationFrameworkStaticIgnoresTheFilesInsideDotFolders()
    {
        await this.test('applicationFramework.static answers 404 for the files inside a dot folder', async () => {
            let appServerFactory = this.builder.createFactory({});
            appServerFactory.app.use(
                this.staticsPath,
                appServerFactory.applicationFramework.static(this.builder.fixturesPath)
            );
            await this.assertFixtureStatics(appServerFactory, 404);
        });
    }

    async testTheApplicationFrameworkStaticKeepsAnExplicitDotfilesOption()
    {
        await this.test('applicationFramework.static keeps the dotfiles option given by the caller', async () => {
            let appServerFactory = this.builder.createFactory({});
            appServerFactory.app.use(
                this.staticsPath,
                appServerFactory.applicationFramework.static(
                    this.builder.fixturesPath,
                    {dotfiles: 'deny', fallthrough: false}
                )
            );
            await this.assertFixtureStatics(appServerFactory, 403);
        });
    }

    async testTheApplicationFrameworkKeepsTheExpressModule()
    {
        await this.test('applicationFramework keeps the express members and creates express applications', () => {
            let applicationFramework = new AppServerFactory().applicationFramework;
            this.assert.strictEqual(applicationFramework.Router, express.Router);
            this.assert.strictEqual(applicationFramework.json, express.json);
            this.assert.strictEqual('function', typeof applicationFramework().handle);
        });
    }

}

module.exports.TestAppServerFactoryStatics = TestAppServerFactoryStatics;
