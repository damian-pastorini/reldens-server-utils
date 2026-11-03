/**
 *
 * Reldens - Server Utils - TestPackageResolver
 *
 */

const { BaseTest } = require('./base-test');
const { PackageResolver } = require('../lib/package-resolver');
const { FileHandler } = require('../lib/file-handler');

class TestPackageResolver extends BaseTest
{

    constructor()
    {
        super();
        this.projectPath = FileHandler.joinPaths(__dirname, '..');
        this.installedPackage = 'express';
        this.missingPackage = 'reldens-missing-package-for-tests';
    }

    async testTheLoadPackageReturnsAnInstalledPackageFromTheProjectPath()
    {
        await this.test('loadPackage returns the package installed in the project path', () => {
            let loadedPackage = PackageResolver.loadPackage(this.installedPackage, this.projectPath);
            this.assert.strictEqual(loadedPackage, require(this.installedPackage));
            this.assert.strictEqual(PackageResolver.error.message, '');
        });
    }

    async testTheLoadPackageReturnsAnInstalledPackageWithoutAProjectPath()
    {
        await this.test('loadPackage returns the installed package without a project path', () => {
            this.assert.strictEqual(PackageResolver.loadPackage(this.installedPackage), require(this.installedPackage));
        });
    }

    async testTheLoadPackageReturnsFalseAndSetsTheErrorForAMissingPackage()
    {
        await this.test('loadPackage returns false and sets the install message for a missing package', () => {
            this.assert.strictEqual(PackageResolver.loadPackage(this.missingPackage, this.projectPath), false);
            this.assert.strictEqual(
                PackageResolver.error.message,
                'Package "'+this.missingPackage+'" not found, install it in the project: npm install '+this.missingPackage
            );
            this.assert.strictEqual(PackageResolver.error.packageName, this.missingPackage);
            this.assert.strictEqual(PackageResolver.error.projectPath, this.projectPath);
        });
    }

    async testTheLoadPackageClearsThePreviousError()
    {
        await this.test('loadPackage clears the error of the previous missing package', () => {
            PackageResolver.loadPackage(this.missingPackage, this.projectPath);
            PackageResolver.loadPackage(this.installedPackage, this.projectPath);
            this.assert.strictEqual(PackageResolver.error.message, '');
        });
    }

}

module.exports.TestPackageResolver = TestPackageResolver;
