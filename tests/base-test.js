/**
 *
 * Reldens - Server Utils - BaseTest
 *
 */

const assert = require('assert');

class BaseTest
{

    constructor()
    {
        this.assert = assert;
        this.testCount = 0;
        this.passedCount = 0;
    }

    async test(name, testCallback)
    {
        this.testCount++;
        try {
            await testCallback();
            this.passedCount++;
            process.stdout.write('PASS: '+name+'\n');
        } catch(error) {
            process.stdout.write('FAIL: '+name+' - '+error.message+'\n');
        }
    }

}

module.exports.BaseTest = BaseTest;
