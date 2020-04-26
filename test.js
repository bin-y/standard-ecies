'use strict';
const crypto = require('crypto');
const assert = require('assert');
const ecies = require('./main.js');

describe('basic test', function () {
  it('decryption result should be same as original text', function () {
    // option parameter is optional, all options are optional except iv,
    // when symmetric cipher is not in ecb mode, iv option must be offered. 

    // default option 
    const options = {
      hashName: 'sha256',
      hashLength: 32,
      macName: 'sha256',
      macLength: 32,
      curveName: 'secp256k1',
      symmetricCypherName: 'aes-128-ecb',
      iv: null,
      // iv is used in symmetric cipher, set null if you want to use cipher
      // in ecb mode. set undefined if you want to use deprecated
      // createCipheriv / createDecipher / EVP_BytesToKey
      keyFormat: 'uncompressed',
      s1: null, // optional shared information1
      s2: null // optional shared information2
    }
    const ecdh = crypto.createECDH(options.curveName);
    ecdh.generateKeys();

    const plainText = Buffer.from ? Buffer.from('hello world') : new Buffer('hello world');
    const encryptedText = ecies.encrypt(ecdh.getPublicKey(), plainText, options);
    const decryptedText = ecies.decrypt(ecdh, encryptedText, options);
    assert(plainText.toString('hex') == decryptedText.toString('hex'));
  });
});