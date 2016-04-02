# standard-ecies
Standard ECIES implemention for NodeJS based on `crypto` module with no other dependencies.

## Motivation
I have tried most of ECIES implemention published on npm, but none of them is exactly what I wanted.
[sjcl](https://www.npmjs.com/package/sjcl) and [secp256k1](https://www.npmjs.com/package/secp256k1) 
are not friendly for windows users when compiling their code, so the projects based on them like 
[eccjs](https://www.npmjs.com/package/eccjs) and [eccrypto](https://www.npmjs.com/package/eccrypto)
are not easy for windows users, either.
[bitcore-ecies](https://www.npmjs.com/package/bitcore-ecies) is friendly for windows but its 
implemention is customized for author's own purpose, not widely applicable.

## Implementation
The implemention is followed by the description in https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme

## Usage
```javascript
const crypto = require('crypto');
const ecies = require('standard-ecies');

// option parameter is optional, all options are optional except iv,
// when symmetric cipher is not in ecb mode, iv option must be offered. 

// default option 
var eciesOptions = {
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

var plainText = 'hello world';
var encryptedText = ecies.encrypt(ecdh.getPublicKey(), plainText, options);
var decryptedText = ecies.decrypt(ecdh.getPrivateKey(), encryptedText, options);
assert(plainText == decryptedText.toString());
```
