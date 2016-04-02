'use strict';
const crypto = require('crypto');
const assert = require('assert');
var ecies = require('./main.js');

describe('basic test', function() {
    it('decryption result should be same as original text', function() {
        // option parameter is optional, all options are optional except iv,
        // when symmetric cipher is not in ecb mode, iv option must be offered. 

        // default option 
        var options = {
            hashName: 'sha256',
            hashLength: 32,
            macName: 'sha256',
            macLength: 32,
            curveName: 'secp256k1',
            symmetricCypherName: 'aes-256-ecb',
            iv: null, // iv is used in symmetric cipher, set null if cipher is in ECB mode. 
            keyFormat: 'uncompressed',
            s1: null, // optional shared information1
            s2: null // optional shared information2
        }
        var ecdh = crypto.createECDH(options.curveName);
        ecdh.generateKeys();

        var plainText = new Buffer('hello world');
        var encryptedText = ecies.encrypt(ecdh.getPublicKey(), plainText, options);
        var decryptedText = ecies.decrypt(ecdh, encryptedText, options);
        assert(plainText.toString('hex') == decryptedText.toString('hex'));
    });
});