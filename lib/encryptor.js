/**
 *
 * Reldens - Encryptor
 *
 */

const crypto = require('crypto');

class Encryptor
{

    constructor()
    {
        this.iterations = 100000;
        this.keylen = 64;
        this.digest = 'sha512';
        this.saltLength = 32;
        this.algorithm = 'aes-256-gcm';
        this.ivLength = 16;
    }

    encryptPassword(password)
    {
        if(!password || 'string' !== typeof password){
            return false;
        }
        let salt = crypto.randomBytes(this.saltLength);
        let hash = crypto.pbkdf2Sync(password, salt, this.iterations, this.keylen, this.digest);
        return salt.toString('hex') + ':' + hash.toString('hex');
    }

    validatePassword(password, storedPassword)
    {
        if(!password || !storedPassword || 'string' !== typeof password || 'string' !== typeof storedPassword){
            return false;
        }
        let parts = storedPassword.split(':');
        if(2 !== parts.length){
            return false;
        }
        let salt = Buffer.from(parts[0], 'hex');
        let storedHash = parts[1];
        let hash = crypto.pbkdf2Sync(password, salt, this.iterations, this.keylen, this.digest);
        return hash.toString('hex') === storedHash;
    }

    generateSecretKey()
    {
        return crypto.randomBytes(32).toString('hex');
    }

    encryptData(data, key)
    {
        if(!data || !key){
            return false;
        }
        let iv = crypto.randomBytes(this.ivLength);
        let cipher = crypto.createCipher(this.algorithm, key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        let authTag = cipher.getAuthTag();
        return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
    }

    decryptData(encryptedData, key)
    {
        if(!encryptedData || !key || 'string' !== typeof encryptedData){
            return false;
        }
        let parts = encryptedData.split(':');
        if(3 !== parts.length){
            return false;
        }
        try {
            let iv = Buffer.from(parts[0], 'hex');
            let authTag = Buffer.from(parts[1], 'hex');
            let encrypted = parts[2];
            let decipher = crypto.createDecipher(this.algorithm, key, iv);
            decipher.setAuthTag(authTag);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            return false;
        }
    }

    generateSecureToken(length = 32)
    {
        if(0 >= length || 256 < length){
            return false;
        }
        return crypto.randomBytes(length).toString('base64url');
    }

    generateTOTP(secret, timeStep = 30)
    {
        if(!secret || 'string' !== typeof secret){
            return false;
        }
        let time = Math.floor(Date.now() / 1000 / timeStep);
        let timeBuffer = Buffer.allocUnsafe(8);
        timeBuffer.writeUInt32BE(0, 0);
        timeBuffer.writeUInt32BE(time, 4);
        let hmac = crypto.createHmac('sha1', Buffer.from(secret, 'base32'));
        hmac.update(timeBuffer);
        let digest = hmac.digest();
        let offset = digest[digest.length - 1] & 0x0f;
        let code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;
        return code.toString().padStart(6, '0');
    }

    hashData(data, algorithm = 'sha256')
    {
        if(!data){
            return false;
        }
        let validAlgorithms = ['sha256', 'sha512', 'md5'];
        if(-1 === validAlgorithms.indexOf(algorithm)){
            return false;
        }
        return crypto.createHash(algorithm).update(data).digest('hex');
    }

    generateHMAC(data, secret, algorithm = 'sha256')
    {
        if(!data || !secret){
            return false;
        }
        let validAlgorithms = ['sha256', 'sha512'];
        if(-1 === validAlgorithms.indexOf(algorithm)){
            return false;
        }
        return crypto.createHmac(algorithm, secret).update(data).digest('hex');
    }

    verifyHMAC(data, secret, signature, algorithm = 'sha256')
    {
        if(!data || !secret || !signature){
            return false;
        }
        let expectedSignature = this.generateHMAC(data, secret, algorithm);
        if(!expectedSignature){
            return false;
        }
        return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
    }

    constantTimeCompare(a, b)
    {
        if(!a || !b || 'string' !== typeof a || 'string' !== typeof b){
            return false;
        }
        if(b.length !== a.length){
            return false;
        }
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }

}

module.exports.Encryptor = new Encryptor();
