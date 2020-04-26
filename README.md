# standard-ecies [![Build Status](https://travis-ci.org/bin-y/standard-ecies.svg?branch=master)](https://travis-ci.org/bin-y/standard-ecies)
Standard ECIES (ecc encryption) implemention for NodeJS based on `crypto` module with no other dependencies.

## Implementation
The implemention is followed by the description in https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme .

Support all of curves listed in `crypto.getCurves()`.

## Usage
```javascript
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
  // iv is used in symmetric cipher, set null if the cipher does not need an
  // initialization vector (e.g. a cipher in ecb mode). Set undefined if you
  // want to use deprecated createCipheriv / createDecipher / EVP_BytesToKey
  keyFormat: 'uncompressed',
  s1: null, // optional shared information1
  s2: null // optional shared information2
}
const ecdh = crypto.createECDH(options.curveName);
ecdh.generateKeys();

const plainText = Buffer.from('hello world');
const encryptedText = ecies.encrypt(ecdh.getPublicKey(), plainText, options);
const decryptedText = ecies.decrypt(ecdh, encryptedText, options);
assert(plainText.toString('hex') == decryptedText.toString('hex'));
```

## Porting from 1.0.0 to 2.0.0
For the projects used this library with options.iv set to a valid iv buffer, no change is required to make compatible with 1.0.0. Other projects can set `options.iv = undefined` to make compatible with an older version.

In the version 1.0.0, it is advised to use a null iv for ECB mode ciphers, which will use crypto.createCipher -> EVP_BytesToKey to derive a key. However, as noted in [the latest manual of EVP_BytesToKey](https://www.openssl.org/docs/man1.1.0/man3/EVP_BytesToKey.html) that "Newer applications should use a more modern algorithm such as PBKDF2 as defined in PKCS#5v2.1 and provided by PKCS5_PBKDF2_HMAC", crypto.createCipher is deprecated by nodejs. Therefore, to avoid this library to use deprecated nodejs API by default, the behavior of `options.iv == null` now is to use crypto.createCipheriv with an empty iv to create the cipher which, however, is incompatible with the cipher created by crypto.createCipher.
