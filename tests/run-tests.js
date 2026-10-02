/**
 *
 * Reldens - Server Utils - RunTests
 *
 */

const { TestEncryptor } = require('./test-encryptor');
const { TestIpListsConfigurer } = require('./test-ip-lists-configurer');
const { TestClientAddressGuard } = require('./test-client-address-guard');
const { TestPackageResolver } = require('./test-package-resolver');
const { TestExpressModuleReexports } = require('./test-express-module-reexports');

class RunTests
{

    constructor()
    {
        this.testClasses = [
            TestEncryptor,
            TestIpListsConfigurer,
            TestClientAddressGuard,
            TestPackageResolver,
            TestExpressModuleReexports
        ];
        this.testCount = 0;
        this.passedCount = 0;
    }

    async run()
    {
        for(let testClass of this.testClasses){
            await this.runTestClass(new testClass());
        }
        let failedCount = this.testCount - this.passedCount;
        process.stdout.write('Total: '+this.testCount+' | Passed: '+this.passedCount+' | Failed: '+failedCount+'\n');
        if(0 < failedCount){
            process.exitCode = 1;
        }
        return 0 === failedCount;
    }

    async runTestClass(testInstance)
    {
        process.stdout.write('Running '+testInstance.constructor.name+'\n');
        for(let methodName of Object.getOwnPropertyNames(Object.getPrototypeOf(testInstance))){
            if(!methodName.startsWith('test')){
                continue;
            }
            await testInstance[methodName]();
        }
        this.testCount += testInstance.testCount;
        this.passedCount += testInstance.passedCount;
    }

}

new RunTests().run();
