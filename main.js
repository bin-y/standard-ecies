// Implemention of ECIES specified in https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
'use strict';

const crypto = require('crypto');
const assert = require('assert');
const empty_buffer = Buffer.allocUnsafe ? Buffer.allocUnsafe(0) : new Buffer([]);

// E
function symmetricEncrypt(cypherName, iv, key, plaintext) {
  let cipher;
  if (iv === undefined) {
    cipher = crypto.createCipher(cypherName, key);
  }
  else {
    if (iv == null) {
      // to support node 6.x
      iv = empty_buffer;
    }
    cipher = crypto.createCipheriv(cypherName, key, iv);
  }
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// E-1
function symmetricDecrypt(cypherName, iv, key, ciphertext) {
  let cipher;
  if (iv === undefined) {
    cipher = crypto.createDecipher(cypherName, key);
  }
  else {
    if (iv == null) {
      // to support node 6.x
      iv = empty_buffer;
    }
    cipher = crypto.createDecipheriv(cypherName, key, iv);
  }
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// KDF
function hashMessage(cypherName, message) {
  return crypto.createHash(cypherName).update(message).digest();
}

// MAC
function macMessage(cypherName, key, message) {
  return crypto.createHmac(cypherName, key).update(message).digest();
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < b1.length; i++) {
    result |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return result === 0;
}

function makeUpOptions(options) {
  options = options || {};
  if (options.hashName == undefined) {
    options.hashName = 'sha256';
  }
  if (options.hashLength == undefined) {
    options.hashLength = hashMessage(options.hashName, '').length;
  }
  if (options.macName == undefined) {
    options.macName = 'sha256';
  }
  if (options.macLength == undefined) {
    options.macLength = macMessage(options.hashName, '', '').length;
  }
  if (options.curveName == undefined) {
    options.curveName = 'secp256k1';
  }
  if (options.symmetricCypherName == undefined) {
    options.symmetricCypherName = 'aes-128-ecb';
    // use options.iv to determine is the cypher in ecb mode
    options.iv = empty_buffer;
  }
  if (options.keyFormat == undefined) {
    options.keyFormat = 'uncompressed';
  }

  // S1 (optional shared information1)
  if (options.s1 == undefined) {
    options.s1 = empty_buffer;
  }
  // S2 (optional shared information2)
  if (options.s2 == undefined) {
    options.s2 = empty_buffer;
  }
  return options;
}

exports.encrypt = function (publicKey, message, options) {
  options = makeUpOptions(options);

  const ecdh = crypto.createECDH(options.curveName);
  // R
  const R = ecdh.generateKeys(null, options.keyFormat);
  // S
  const sharedSecret = ecdh.computeSecret(publicKey);

  // uses KDF to derive a symmetric encryption and a MAC keys:
  // Ke || Km = KDF(S || S1)
  const hash = hashMessage(
    options.hashName,
    Buffer.concat(
      [sharedSecret, options.s1],
      sharedSecret.length + options.s1.length
    )
  );
  // Ke
  const encryptionKey = hash.slice(0, hash.length / 2);
  // Km
  const macKey = hash.slice(hash.length / 2);

  // encrypts the message:
  // c = E(Ke; m);
  const cipherText = symmetricEncrypt(options.symmetricCypherName, options.iv, encryptionKey, message);

  // computes the tag of encrypted message and S2: 
  // d = MAC(Km; c || S2)
  const tag = macMessage(
    options.macName,
    macKey,
    Buffer.concat(
      [cipherText, options.s2],
      cipherText.length + options.s2.length
    )
  );
  // outputs R || c || d
  return Buffer.concat([R, cipherText, tag]);
};

exports.decrypt = function (ecdh, message, options) {
  options = makeUpOptions(options);

  const publicKeyLength = ecdh.getPublicKey(null, options.keyFormat).length;
  // R
  const R = message.slice(0, publicKeyLength);
  // c
  const cipherText = message.slice(publicKeyLength, message.length - options.macLength);
  // d
  const messageTag = message.slice(message.length - options.macLength);

  // S
  const sharedSecret = ecdh.computeSecret(R);

  // derives keys the same way as Alice did:
  // Ke || Km = KDF(S || S1)
  const hash = hashMessage(
    options.hashName,
    Buffer.concat(
      [sharedSecret, options.s1],
      sharedSecret.length + options.s1.length
    )
  );
  // Ke
  const encryptionKey = hash.slice(0, hash.length / 2);
  // Km
  const macKey = hash.slice(hash.length / 2);

  // uses MAC to check the tag
  const keyTag = macMessage(
    options.macName,
    macKey,
    Buffer.concat(
      [cipherText, options.s2],
      cipherText.length + options.s2.length
    )
  );

  // outputs failed if d != MAC(Km; c || S2);
  assert(equalConstTime(messageTag, keyTag), "Bad MAC");

  // uses symmetric encryption scheme to decrypt the message
  // m = E-1(Ke; c)
  return symmetricDecrypt(options.symmetricCypherName, options.iv, encryptionKey, cipherText);
}
