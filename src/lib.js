/**
 *  A collection of stateless functions to help with all the crypto.
 *  @module Lib
 *  @author Francis J.. Van Wetering IV
 */
var crypto = require('crypto'),
    constants = require('constants'),
    CryptoError = require('./errors/crypto'),
    /**
     *  The Delimiter for RSA Encryptions
     *  @default
     */
    DELIMITER = ':',
    /**
     *  Tolerance for out of synch clocks
     *  @default
     */
    STALE_REQUEST_TOLERANCE = 60000 // One minute clock drift allowed.
    ;

module.exports = exports = {

    /**
     *  Generate a nonce.  Currently, Nonces are essentially 53bits of cryptographically insecure
     *  randomness, but their integer nature is kind of immaterial.
     *  
     *  @returns {Number} A positive Integer, for now.  Really, this could return any data, in any size.
     *  @function nonce
     *  @static
     */
    nonce: function() {
        return Math.floor(Math.random() * Number.MAX_SAFE_INTEGER) + 1
    },

    /**
     *  Generate a one-time use key for encrypting messages via RSA.
     *  
     *  @param {module:Lib~randomCallback} callback Will be called with 32 random bytes or an error.
     *  @static
     */
    oneTimeKey: function(callback) {
        try {
            crypto.randomBytes(32, function(err, key) {
                if (callback) {
                    if (err)
                        callback(new CryptoError.RandomBytesError(err));
                    else 
                        callback(null, key);
                }
            });
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.RandomBytesError(err));
                });
        }
    },

    /**
     *  Generate a short use key for consumer/provider authentication.
     *  
     *  @param {module:Lib~randomCallback} callback Will be called with 64 random bytes or an error.
     *  @static
     */
    shortUseKey: function(callback) {
        try {
            crypto.randomBytes(64, function(err, key) {
                if (callback) {
                    if (err)
                        callback(new CryptoError.RandomBytesError(err));
                    else 
                        callback(null, key);
                }
            });
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.RandomBytesError(err));
                });
        }
    },

    /**
     *  Decipher a symmetrically encrypted ciphertext.
     *  
     *  @param {Buffer|String} ciphertext Either a buffer with cipher bytes, or a base64 encoded string.
     *  @param {Buffer|String} key Either a buffer with key bytes, or a base64 encoded string.
     *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
     *  @param {module:Lib~decipherCallback} callback A callback for the eventual error or plaintext.
     *  @static
     */
    decipher: function(ciphertext, key, algorithm, callback) {
        try {
            if (!(ciphertext instanceof Buffer))
                ciphertext = new Buffer(ciphertext, 'base64');
            if (!(key instanceof Buffer))
                key = new Buffer(key, 'base64');
            var decipher = crypto.createDecipher(algorithm, key);
            decipher.end(ciphertext, function() {
                try {
                    var plaintext = decipher.read().toString('utf8');
                    if (callback) callback(null, plaintext);
                } catch (err) {
                    if (callback)
                        callback(new CryptoError.CipherError(err));
                }
            });
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.CipherError(err));
                });
        }
    },

    /**
     *  Decipher a symmetrically encrypted ciphertext.
     *  
     *  @param {Buffer|String} message Either a buffer with plaintext bytes, or a utf8 encoded string.
     *  @param {Buffer|String} key Either a buffer with key bytes, or a base64 encoded string.
     *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
     *  @param {module:Lib~encipherCallback} callback A callback for the eventual error or plaintext.
     *  @static
     */
    encipher: function(message, key, algorithm, callback) {
        try {
            if (!(message instanceof Buffer))
                message = new Buffer(message, 'utf8');
            if (!(key instanceof Buffer))
                key = new Buffer(key, 'base64');
            var cipher = crypto.createCipher(algorithm, key);
            cipher.end(message, function() {
                try {
                    var cipherText = cipher.read().toString('base64');
                    if (callback) callback(null, cipherText);
                } catch (err) {
                    if (callback)
                        callback(new CryptoError.CipherError(err));
                }
            });
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.CipherError(err));
                });
        }
    },

    /**
     *  Encipher the data in question (via JSON Encoded String) with a one-time 256bit key, then 
     *  encrypt the key with the provided RSA key.  The two ciphertexts are then base64 encoded 
     *  and joined with a delimeter to provide the Encrypted Text.
     *  
     *  @param {Buffer|String} rsaKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} message Either a buffer with plaintext bytes, or a utf8 encoded string.
     *  @param {String} algorithm The cipher algorithm to use while enciphering.
     *  @param {module:Lib~encryptCallback} callback A callback for the eventual error or ciphertext.
     *  @static
     */
    encrypt: function(rsaKey, data, algorithm, callback) {
        try {
            var that = this;
            this.oneTimeKey(function(err, cipherKey) {
                try {
                    if (err) {
                        callback(err)
                        return;
                    }
                    that.encipher(data, cipherKey, algorithm, function(err, cipherText) {
                        try{
                            if (err) {
                                callback(err)
                                return;
                            }
                            var unlock = {
                                algorithm: algorithm
                                , key: cipherKey.toString('base64')
                            }
                            , unlockEncrypted = crypto.publicEncrypt(rsaKey, new Buffer(JSON.stringify(unlock), 'utf8'))
                            , encryptedMessage = cipherText + DELIMITER + unlockEncrypted.toString('base64')
                            ;
                            if (callback) callback(null, encryptedMessage);
                        } catch (err) {
                            if (callback)
                                callback(new CryptoError.RSAError(err));
                        }
                    });
                } catch (err) {
                    if (callback)
                        callback(new CryptoError.RSAError(err));
                }
            });
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.RSAError(err));
                });
        }
    },

    /**
     *  Decrypt the output of the encrypt function.
     *  
     *  @param {Buffer|String} rsaKey A PEM Encoded RSA Key (Private Key)
     *  @param {Buffer|String} data The output of a previous call to Encrypt
     *  @param {module:Lib~decryptCallback} callback A callback for the eventual error or plaintext
     *  @static
     */
    decrypt: function(rsaKey, data, callback) {
        try {
            var pieces = data.split(DELIMITER)
                , message = pieces[0]
                , locked = pieces[1]
                , key = JSON.parse(crypto.privateDecrypt(rsaKey, new Buffer(locked, 'base64')).toString())
                ;
            this.decipher(message, key.key, key.algorithm, function(err, plainText) {
                try{
                    if (err) {
                        callback(err)
                        return;
                    }
                    if (callback) callback(null, JSON.parse(plainText));
                } catch (err) {
                    if (callback)
                        callback(new CryptoError.RSAError(err));
                }
            });//*/
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.RSAError(err));
                });
        }
    },

    /**
     *  Sign some Data.
     *  
     *  @param {Buffer|String} rsaKey A PEM Encoded RSA Key (Private Key)
     *  @param {Buffer|String} data The data to be signed.
     *  @param {String} algorithm The Hash algorithm to use whilst calculating the HMAC
     *  @param {module:Lib~signCallback} callback A callback for the eventual error or signature
     *  @static
     */
    sign: function(rsaKey, data, algorithm, callback) {
        try {
            var signer = crypto.createSign(algorithm);
            signer.end(new Buffer(data), function() {
                try {
                    var signature = signer.sign(rsaKey).toString('base64');
                    if(callback) callback(null, signature);
                } catch (err) {
                    if (callback)
                        callback(new CryptoError.RSAError(err));
                }
            });
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.RSAError(err));
                });
        }
    },

    /**
     *  Verify a Signature.
     *  
     *  @param {Buffer|String} rsaKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} data The previously signed data.
     *  @param {String} algorithm The Hash algorithm to use whilst calculating the HMAC
     *  @param {Buffer|String} signature The previously generated Signature - as a buffer or base64
     *      encoded String.
     *  @param {module:Lib~verifyCallback} callback A callback for the eventual error or verification Status
     *  @static
     */
    verify: function(rsaKey, data, algorithm, signature, callback) {
        try {
            if (!(data instanceof Buffer))
                new Buffer(data, 'base64');
            var verifier = crypto.createVerify(algorithm);
            verifier.end(data, function() {
                try {
                    var verified = verifier.verify(rsaKey, signature, 'base64');
                    if(callback) callback(null, verified);
                } catch (err) {
                    if (callback)
                        callback(new CryptoError.RSAError(err));
                }
            });
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new CryptoError.RSAError(err));
                });
        }
    },

    /**
     *  Check if a timstamp is stale - gathered here for repitition's sake.
     *  
     *  @param {Number} - A numeric timestamp in milliseconds since the epoch.
     *  @returns {Boolean} - True if the timestamp in question is too far out of synch with the server's clock.
     *  @static
     */
    isStale: function(ts) {
        return !ts || Math.abs(ts - new Date().getTime()) > STALE_REQUEST_TOLERANCE
    },
    
    /**
     *  Encrypt and Sign - a simple concatentation of {@link module:Lib.encrypt encrypt} and {@link module:Lib.sign sign}.
     *  
     *  @param {Buffer|String} encryptKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} signKey A PEM Encoded RSA Key (Private Key)
     *  @param {Buffer|String} message Either a buffer with plaintext bytes, or a utf8 encoded string.
     *  @param {String} cipher The cipher algorithm to use while enciphering.
     *  @param {String} hash The Hash algorithm to use whilst calculating the HMAC
     *  @param {module:Lib~encryptAndSignCallback} callback A callback for the eventual error or encrypted/signed message.
     */
    encryptAndSign: function(encryptKey, signKey, message, cipher, hash, callback) {
        var that = this;
        this.encrypt(encryptKey, message, cipher, function(err, cipherText) {
            if (err) {
                callback(err);
                return;
            }
            that.sign(signKey, cipherText, hash, function(err, signature) {
                if (err)
                    callback(err)
                else
                    callback(null, {
                        "message": cipherText
                        , "signature": signature
                    });
            });
        });
    },

    /**
     *  Decrypt and Verify - a simple concatentation of {@link module:Lib.decrypt decrypt} and {@link module:Lib.verify verify}
     *  
     *  @param {Buffer|String} encryptKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} signKey A PEM Encoded RSA Key (Private Key)
     *  @param {Object} The over the wire message - shaped like output from {@link module:Lib.encryptAndSign encryptAndSign}
     *  @param {module:Lib~decryptAndVerifyCallback} callback A callback for the eventual error or plaintext
     */
    decryptAndVerify: function(decryptKey, verifyKey, message, callback) {
        var that = this;
        this.decrypt(decryptKey, message.message, function(err, plaintext) {
            if (err) {
                callback(err);
                return;
            }
            that.verify(verifyKey, message.message, plaintext.hash, message.signature, function(err, verified) {
                if (err) 
                    callback(err);
                else if (!verified)
                    callback(new CryptoError.VerificationError());
                else
                    callback(null, plaintext);
            });
        });
    },

    /**
     *  A list of all the supported ciphers.
     *  @static
     *  @default
     */
    ciphers: crypto.getCiphers(),

    /**
     *  A Hash to check if a cipher is supported.
     *  @static
     *  @default
     */
    cipherCheck: arrayToHashKeys(crypto.getCiphers()),

    /**
     *  A list of all supported Hashing Algorithms.
     *  @static
     *  @default
     */
    hashes: crypto.getHashes(),

    /**
     *  A Hash to check if a hashing algorithm is supported.
     *  @static
     *  @default
     */
    hashCheck: arrayToHashKeys(crypto.getHashes())
}

/**
 *  Switch an array's contents to hash keys to make inArray checks cheaper.
 *  
 *  @param {array} array Any array
 *  @return {Object} An object whose keys consist of the items in the array,
 *    and the values assosciated with those keys are boolean true.
 *  @static
 */
function arrayToHashKeys(array) {
    var toReturn = {};
    for (var i = 0; i < array.length; i++)
        toReturn[array[i]] = true;
    return toReturn;
}

/**
 *  Callback for functions generating random bytes.
 *  @callback module:Lib~randomCallback
 *  @param {ServerosError} error Any Error that prevents generation of random bytes.
 *  @param {Buffer} key A buffer with the correct number of bytes.
 */

/**
 *  Callback for decipher
 *  @callback module:Lib~decipherCallback
 *  @param {ServerosError} error Any Error that prevents deciphering
 *  @param {String} plaintext A UTF8 Encoded Plaintext string
 */

/**
 *  Callback for encipher
 *  @callback module:Lib~encipherCallback
 *  @param {ServerosError} error Any Error that prevents deciphering
 *  @param {String} ciphertext A base64 Encoded Ciphertext string
 */

/**
 *  Callback for encrypt
 *  @callback module:Lib~encryptCallback
 *  @param {ServerosError} error Any Error that prevents Encryption
 *  @param {String} ciphertext A base64 Encoded Ciphertext string
 */

/**
 *  Callback for decrypt
 *  @callback module:Lib~decryptCallback
 *  @param {ServerosError} error Any Error that prevents Decryption
 *  @param {String} ciphertext A UTF-8 Encoded Plaintext string
 */

/**
 *  Callback for sign
 *  @callback module:Lib~signCallback
 *  @param {ServerosError} error Any Error that prevents Decryption
 *  @param {String} signature The Base64 Signature.
 */

/**
 *  Callback for verify
 *  @callback module:Lib~verifyCallback
 *  @param {ServerosError} error Any Error that prevents Decryption
 *  @param {Boolean} verified True if the signature matches, false if it does not.
 */

/**
 *  Callback for encryptAndSign
 *  @callback module:Lib~encryptAndSignCallback
 *  @param {ServerosError} error Any Error that prevents Decryption
 *  @param {Object} message Encrypted and signed messages.
 */

/**
 *  Callback for module:Lib~decryptAndVerify
 *  @callback decryptAndVerifyCallback
 *  @param {ServerosError} error Any Error that prevents Decryption or Verification
 *  @param {Object} plaintext the plaintext message, if verified.
 */
