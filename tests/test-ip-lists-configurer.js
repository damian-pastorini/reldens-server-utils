/**
 *
 * Reldens - Server Utils - TestIpListsConfigurer
 *
 */

const { BaseTest } = require('./base-test');
const { IpListsConfigurer } = require('../lib/app-server-factory/ip-lists-configurer');

class TestIpListsConfigurer extends BaseTest
{

    constructor()
    {
        super();
        this.invalidPrefixEntries = ['10.0.0.0/33', '10.0.0.0/abc', '10.0.0.0/', '10.0.0.0/8/8', '2001:db8::/129'];
        this.validPrefixEntries = ['10.0.0.0/8', '2001:db8::/32'];
    }

    createIpListsConfigurer(allow, deny)
    {
        let ipListsConfigurer = new IpListsConfigurer();
        ipListsConfigurer.setLists({enabled: true, allow, deny});
        return ipListsConfigurer;
    }

    async testTheInvalidPrefixesAreIgnoredWithoutThrowing()
    {
        await this.test('the invalid CIDR prefixes are ignored without throwing and block nothing', () => {
            let ipListsConfigurer = this.createIpListsConfigurer([], this.invalidPrefixEntries);
            this.assert.strictEqual(ipListsConfigurer.hasDenyEntries, false);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('8.8.8.8'), true);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('10.1.2.3'), true);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('2001:db8::1'), true);
        });
    }

    async testTheValidPrefixesDenyTheAddressesInTheirRanges()
    {
        await this.test('the valid IPv4 and IPv6 prefixes deny the addresses in their ranges', () => {
            let ipListsConfigurer = this.createIpListsConfigurer([], this.validPrefixEntries);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('10.1.2.3'), false);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('::ffff:10.1.2.3'), false);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('2001:db8::1'), false);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('8.8.8.8'), true);
        });
    }

    async testTheInvalidAddressIsAllowedWithoutAllowEntries()
    {
        await this.test('an invalid address is allowed when there are no allow entries', () => {
            let ipListsConfigurer = this.createIpListsConfigurer([], this.validPrefixEntries);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('not-an-ip'), true);
            this.assert.strictEqual(ipListsConfigurer.isAllowed(''), true);
        });
    }

    async testTheInvalidAddressIsDeniedWithAllowEntries()
    {
        await this.test('an invalid or empty address is denied when there are allow entries', () => {
            let ipListsConfigurer = this.createIpListsConfigurer(['127.0.0.1'], []);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('not-an-ip'), false);
            this.assert.strictEqual(ipListsConfigurer.isAllowed(''), false);
            this.assert.strictEqual(ipListsConfigurer.isAllowed('127.0.0.1'), true);
        });
    }

}

module.exports.TestIpListsConfigurer = TestIpListsConfigurer;
