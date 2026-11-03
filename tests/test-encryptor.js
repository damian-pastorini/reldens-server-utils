/**
 *
 * Reldens - Server Utils - TestEncryptor
 *
 */

const { BaseTest } = require('./base-test');
const { Encryptor } = require('../lib/encryptor');

class TestEncryptor extends BaseTest
{

    constructor()
    {
        super();
        this.asciiValue = 'a'.repeat(64);
        this.multiByteValue = 'a'.repeat(63)+'é';
        this.hmacData = 'data';
        this.hmacSecret = 'secret';
        this.hmacSignature = Encryptor.generateHMAC(this.hmacData, this.hmacSecret);
        this.password = 'valid-password';
        this.storedPassword = Encryptor.encryptPassword(this.password);
    }

    async testTheConstantTimeCompareRejectsAMultiByteValueOfTheSameLength()
    {
        await this.test('constantTimeCompare returns false for a multi-byte value of the same length', () => {
            this.assert.strictEqual(Encryptor.constantTimeCompare(this.asciiValue, this.multiByteValue), false);
        });
    }

    async testTheConstantTimeCompareAcceptsEqualValues()
    {
        await this.test('constantTimeCompare returns true for equal values', () => {
            this.assert.strictEqual(Encryptor.constantTimeCompare(this.asciiValue, 'a'.repeat(64)), true);
        });
    }

    async testTheVerifyHmacRejectsAMultiByteSignatureOfTheExpectedLength()
    {
        await this.test('verifyHMAC returns false for a multi-byte signature of the expected length', () => {
            this.assert.strictEqual(this.hmacSignature.length, this.multiByteValue.length);
            this.assert.strictEqual(Encryptor.verifyHMAC(this.hmacData, this.hmacSecret, this.multiByteValue), false);
        });
    }

    async testTheVerifyHmacAcceptsTheGeneratedSignature()
    {
        await this.test('verifyHMAC returns true for the generated signature', () => {
            this.assert.strictEqual(Encryptor.verifyHMAC(this.hmacData, this.hmacSecret, this.hmacSignature), true);
        });
    }

    async testThePasswordValidationMatchesTheStoredHash()
    {
        await this.test('validatePassword resolves true for the stored password and false for others', async () => {
            this.assert.strictEqual(await Encryptor.validatePassword(this.password, this.storedPassword), true);
            this.assert.strictEqual(await Encryptor.validatePassword('invalid', this.storedPassword), false);
        });
    }

    async testThePasswordValidationReturnsAPromise()
    {
        await this.test('validatePassword returns a promise so it does not block the event loop', async () => {
            let validation = Encryptor.validatePassword(this.password, this.storedPassword);
            this.assert.strictEqual(validation instanceof Promise, true);
            this.assert.strictEqual(await validation, true);
        });
    }

    async testThePasswordValidationRejectsAMalformedStoredPassword()
    {
        await this.test('validatePassword resolves false for a malformed or empty stored password', async () => {
            this.assert.strictEqual(await Encryptor.validatePassword(this.password, 'not-a-hash'), false);
            this.assert.strictEqual(await Encryptor.validatePassword(this.password, ''), false);
            this.assert.strictEqual(await Encryptor.validatePassword('', this.storedPassword), false);
        });
    }

}

module.exports.TestEncryptor = TestEncryptor;
