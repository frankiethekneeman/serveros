var crypto = require('crypto'),
    constants = require('constants'),
    cipherData = require('../cipherdata'),
    CryptoError = require('../errors/crypto'),

    /**
     *  The Delimiter for RSA Encryptions
     *  
     *  @memberOf Serveros.Encrypter
     *  @default
     *  @private
     */
    DELIMITER = ':',

    /**
     *  Tolerance for out of synch clocks
     *  
     *  @memberOf Serveros.Encrypter
     *  @default
     *  @private
     */
    STALE_REQUEST_TOLERANCE = 60000 // One minute clock drift allowed.

    /**
     *  A Regular expression to help weed out padding characters.
     *  
     *  PKCS Padding requires you to pad the last N bytes with bytes of value N.  As such, 00-1F
     *  Will work for up to 256 bit block sizes.  Since they're all control characters, I don't
     *  expect to see them in the actual plaintext.  I'm not bothering to verify that the values
     *  match the size.
     *  
     *  ISO 7816 Padding uses the 80 byte followed by 00 bytes till the end.
     *  
     *  Zero Padding is contraindicated by Good Encryption standards, but PHP has to foul up
     *  everything.
     *  
     *  ANSI X.923 Bytes are 00 bytes till the end, but the last byte is 01-1F, indicating the number
     *  of padding bytes needed.  It is not being validated.
     *  
     *  @memberOf Serveros.Encrypter
     *  @default
     */
    PADDING_CHARACTERS = /(?:([\x00-\x1F])\1*|\x80\x00*|\x00*[\x01-\x1F])$/g;
    ;

var ciphers = crypto.getCiphers().filter(function(cipher) {
    return !!(cipherData[cipher]);
});
var hashes = crypto.getHashes();

/**
 *  Switch an array's contents to hash keys to make inArray checks cheaper.
 *  
 *  @param {array} array Any array
 *  @return {Object} An object whose keys consist of the items in the array,
 *    and the values assosciated with those keys are boolean true.
 *  
 *  @memberOf Serveros.Encrypter
 *  @static
 */
function arrayToHashKeys(array) {
    var toReturn = {};
    for (var i = 0; i < array.length; i++)
        toReturn[array[i]] = true;
    return toReturn;
}

/**
 *  A Base class for all encryption classes.
 *  @class Serveros.Encrypter
 *  @author Francis J.. Van Wetering IV
 */
function Encrypter() {
}

Encrypter.prototype = {

    /**
     *  Generate a nonce.  Currently, Nonces are essentially 53bits of cryptographically insecure
     *  randomness, but their integer nature is kind of immaterial.
     *  
     *  @returns {Number} A positive Integer, for now.  Really, this could return any data, in any size.
     */
    nonce: function() {
        return Math.floor(Math.random() * Number.MAX_SAFE_INTEGER) + 1
    },

    /**
     *  Generate a one-time use key for encrypting messages via RSA.
     *  
     *  @param {Serveros.Encrypter~randomCallback} callback Will be called with 32 random bytes or an error.
     */
    oneTimeKey: function(callback) {
        try {
            crypto.randomBytes(32, function(err, key) {
                if (callback) {
                    if (err)
                        callback(new CryptoError.RandomBytesError(err));
                    else 
                        /**
                         *  Callback for functions generating random bytes.
                         *  @callback Serveros.Encrypter~randomCallback
                         *  @param {Error.ServerosError} error Any Error that prevents generation of random bytes.
                         *  @param {Buffer} key A buffer with the correct number of bytes.
                         */
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
     *  Get Single use credentials for a specific cipher.  Gets a key of the right size, and an
     *  initial vector of size equal to the block size for a known ciphers.
     *  
     *  @param {String} cipherName The name of the intended Cipher.
     *  @param {Serveros.Encrypter~credentialsCallback} callback a callback for the eventual credentials.
     */
    getOneTimeCredentials: function(cipherName, callback) {
        var that = this
            , facts = cipherData[cipherName]
            ;
        try {
            if (!(this.cipherCheck[cipherName]) || !facts) {
                if (callback)
                    callback(new CryptoError.UnrecognizedCipherError(cipherName, ciphers));
            } else {
                crypto.randomBytes(Math.ceil(facts.key/8), function(err, key) {
                    if (err) {
                        if (callback)
                            callback(new CryptoError.RandomBytesError(err));
                        return;
                    } else {
                        crypto.randomBytes(Math.ceil(facts.block/8), function(err, iv) {
                            if (err) {
                                if (callback)
                                    callback(new CryptoError.RandomBytesError(err));
                                return;
                            } else {
                                if (callback) 

                                    /**
                                     *  Callback for getOneTimeCredentials
                                     *  @callback Serveros.Encrypter~credentialsCallback
                                     *  @param {Error.ServerosError} error Any Error that prevents generation of random bytes.
                                     *  @param {Object} credentials The key, IV, and name of the cipher.
                                     *  @param {Buffer} credentials.key A random key.
                                     *  @param {Buffer} credentials.iv A random initial Vector
                                     *  @param {String} credentials.algorithm The cipherName passed into {@link Serveros.Encrypter~getOneTimeCredentials}
                                     */
                                    callback(null, {
                                        key: key
                                        , iv: iv
                                        , algorithm: cipherName
                                    });
                            }
                        });
                    }
                });
            }
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
     *  @param {Serveros.Encrypter~randomCallback} callback Will be called with 64 random bytes or an error.
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
     *  @param {Buffer|String} IV Either a buffer with IV bytes, or a base64 encoded string.
     *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
     *  @param {Serveros.Encrypter~decipherCallback} callback A callback for the eventual error or plaintext.
     */
    decipher: function(ciphertext, key, iv, algorithm, callback) {
        try {
            if (this.cipherPrefs.indexOf(algorithm) == -1) {
                if (callback) {
                    var that = this;
                    process.nextTick(function() {
                        callback(new CryptoError.UnsupportedCipherError(algorithm, that.cipherPrefs));
                    });
                }
                return;
            }
            if (!(ciphertext instanceof Buffer))
                ciphertext = new Buffer(ciphertext, 'base64');
            if (!(key instanceof Buffer))
                key = new Buffer(key, 'base64');
            if (!(iv instanceof Buffer))
                iv = new Buffer(iv, 'base64');
            var decipher = crypto.createDecipheriv(algorithm, key, iv);
            decipher.setAutoPadding(false);
            decipher.end(ciphertext, function() {
                try {
                    //Strip P
                    var plaintext = decipher.read().toString('utf8').replace(PADDING_CHARACTERS, '');

                    /**
                     *  Callback for decipher
                     *  @callback Serveros.Encrypter~decipherCallback
                     *  @param {Error.ServerosError} error Any Error that prevents deciphering
                     *  @param {String} plaintext A UTF8 Encoded Plaintext string
                     */
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
     *  @param {Buffer|String} initialVector Either a buffer with IV bytes, or a base64 encoded string.
     *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
     *  @param {Serveros.Encrypter~encipherCallback} callback A callback for the eventual error or plaintext.
     */
    encipher: function(message, key, initialVector, algorithm, callback) {
        try {
            if (this.cipherPrefs.indexOf(algorithm) == -1) {
                if (callback) {
                    var that = this;
                    process.nextTick(function() {
                        callback(new CryptoError.UnsupportedCipherError(algorithm, that.cipherPrefs));
                    });
                }
                return;
            }
            if (!(message instanceof Buffer))
                message = new Buffer(message, 'utf8');
            if (!(key instanceof Buffer))
                key = new Buffer(key, 'base64');
            if (!(initialVector instanceof Buffer))
                initialVector = new Buffer(initialVector, 'base64');
            var cipher = crypto.createCipheriv(algorithm, key, initialVector);
            cipher.end(message, function() {
                try {
                    var cipherText = cipher.read().toString('base64');

                    /**
                     *  Callback for encipher
                     *  @callback Serveros.Encrypter~encipherCallback
                     *  @param {Error.ServerosError} error Any Error that prevents deciphering
                     *  @param {String} ciphertext A base64 Encoded Ciphertext string
                     */
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
     *  Encipher the data in question (via JSON Encoded String) with a one-time key/IV, then 
     *  encrypt the key/IV with the provided RSA key.  The two ciphertexts are then base64 encoded 
     *  and joined with a delimiter to provide the Encrypted Text.
     *  
     *  @param {Buffer|String} rsaKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} message Either a buffer with plaintext bytes, or a utf8 encoded string.
     *  @param {String} algorithm The cipher algorithm to use while enciphering.
     *  @param {Serveros.Encrypter~encryptCallback} callback A callback for the eventual error or ciphertext.
     */
    encrypt: function(rsaKey, data, algorithm, callback) {
        try {
            var that = this;
            this.getOneTimeCredentials(algorithm, function(err, credentials) {
                try {
                    if (err) {
                        callback(err)
                        return;
                    }
                    that.encipher(data, credentials.key, credentials.iv, algorithm, function(err, cipherText) {
                        try{
                            if (err) {
                                callback(err)
                                return;
                            }
                            var lock = {
                                key: credentials.key.toString('base64')
                                , iv: credentials.iv.toString('base64')
                                , algorithm: credentials.algorithm
                            }
                            , unlockEncrypted = crypto.publicEncrypt( {key: rsaKey, padding: constants.RSA_PKCS1_OAEP_PADDING}
                            , new Buffer(JSON.stringify(lock), 'utf8'))
                            , encryptedMessage = cipherText + DELIMITER + unlockEncrypted.toString('base64')
                            ;

                            /**
                             *  Callback for encrypt
                             *  @callback Serveros.Encrypter~encryptCallback
                             *  @param {Error.ServerosError} error Any Error that prevents Encryption
                             *  @param {String} ciphertext A base64 Encoded Ciphertext string
                             */
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
     *  @param {Serveros.Encrypter~decryptCallback} callback A callback for the eventual error or plaintext
     */
    decrypt: function(rsaKey, data, callback) {
        try {
            var pieces = data.split(DELIMITER)
                , message = pieces[0]
                , locked = pieces[1]
                , key = JSON.parse(crypto.privateDecrypt({key: rsaKey, padding: constants.RSA_PKCS1_OAEP_PADDING}
                    , new Buffer(locked, 'base64')).toString())
                ;
            this.decipher(message, key.key, key.iv, key.algorithm, function(err, plainText) {
                try{
                    if (err) {
                        callback(err)
                        return;
                    }
                    /**
                     *  Callback for decrypt
                     *  @callback Serveros.Encrypter~decryptCallback
                     *  @param {Error.ServerosError} error Any Error that prevents Decryption
                     *  @param {String} ciphertext A UTF-8 Encoded Plaintext string
                     */
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
     *  @param {Serveros.Encrypter~signCallback} callback A callback for the eventual error or signature
     */
    sign: function(rsaKey, data, algorithm, callback) {
        try {
            if (this.hashPrefs.indexOf(algorithm) == -1) {
                if (callback) {
                    var that = this;
                    process.nextTick(function() {
                        callback(new CryptoError.UnsupportedHashError(algorithm, that.hashPrefs));
                    });
                }
                return;
            }
            var signer = crypto.createSign(algorithm);
            signer.end(new Buffer(data), function() {
                try {
                    var signature = signer.sign(rsaKey).toString('base64');

                    /**
                     *  Callback for sign
                     *  @callback Serveros.Encrypter~signCallback
                     *  @param {Error.ServerosError} error Any Error that prevents Decryption
                     *  @param {String} signature The Base64 Signature.
                     */
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
     *  @param {Serveros.Encrypter~verifyCallback} callback A callback for the eventual error or verification Status
     */
    verify: function(rsaKey, data, algorithm, signature, callback) {
        try {
            if (this.hashPrefs.indexOf(algorithm) == -1) {
                if (callback) {
                    var that = this;
                    process.nextTick(function() {
                        callback(new CryptoError.UnsupportedHashError(algorithm, that.hashPrefs));
                    });
                }
                return;
            }
            if (!(data instanceof Buffer))
                new Buffer(data, 'base64');
            var verifier = crypto.createVerify(algorithm);
            verifier.end(data, function() {
                try {
                    var verified = verifier.verify(rsaKey, signature, 'base64');

                    /**
                     *  Callback for verify
                     *  @callback Serveros.Encrypter~verifyCallback
                     *  @param {Error.ServerosError} error Any Error that prevents Decryption
                     *  @param {Boolean} verified True if the signature matches, false if it does not.
                     */
                    if(callback) {
                        if (!verified)
                            callback(new CryptoError.VerificationError());
                        else callback(null, verified);
                    }
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
     */
    isStale: function(ts) {
        return !ts || Math.abs(ts - new Date().getTime()) > STALE_REQUEST_TOLERANCE
    },
    
    /**
     *  Encrypt and Sign - a simple concatentation of {@link Serveros.Encrypter.encrypt encrypt} and {@link Serveros.Encrypter.sign sign}.
     *  
     *  @param {Buffer|String} encryptKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} signKey A PEM Encoded RSA Key (Private Key)
     *  @param {Buffer|String} message Either a buffer with plaintext bytes, or a utf8 encoded string.
     *  @param {String} cipher The cipher algorithm to use while enciphering.
     *  @param {String} hash The Hash algorithm to use whilst calculating the HMAC
     *  @param {Serveros.Encrypter~encryptAndSignCallback} callback A callback for the eventual error or encrypted/signed message.
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

                    /**
                     *  Callback for encryptAndSign
                     *  @callback Serveros.Encrypter~encryptAndSignCallback
                     *  @param {Error.ServerosError} error Any Error that prevents Decryption
                     *  @param {Object} message Encrypted and signed messages.
                     */
                    callback(null, {
                        "message": cipherText
                        , "signature": signature
                    });
            });
        });
    },

    /**
     *  Decrypt and Verify - a simple concatentation of {@link Serveros.Encrypter.decrypt decrypt} and {@link Serveros.Encrypter.verify verify}
     *  
     *  @param {Buffer|String} encryptKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} signKey A PEM Encoded RSA Key (Private Key)
     *  @param {Object} The over the wire message - shaped like output from {@link Serveros.Encrypter.encryptAndSign encryptAndSign}
     *  @param {Serveros.Encrypter~decryptAndVerifyCallback} callback A callback for the eventual error or plaintext
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

                    /**
                     *  Callback for Serveros.Encrypter~decryptAndVerify
                     *  @callback Serveros.Encrypter~decryptAndVerifyCallback
                     *  @param {Error.ServerosError} error Any Error that prevents Decryption or Verification
                     *  @param {Object} plaintext the plaintext message, if verified.
                     */
                    callback(null, plaintext);
            });
        });
    },

    /**
     *  A list of all the supported ciphers.
     *  @default
     */
    cipherPrefs: ciphers,

    /**
     *  A Hash to check if a cipher is supported.
     *  @default
     */
    cipherCheck: arrayToHashKeys(ciphers),

    /**
     *  A list of all supported Hashing Algorithms.
     *  @default
     */
    hashPrefs: hashes,

    /**
     *  A Hash to check if a hashing algorithm is supported.
     *  @default
     */
    hashCheck: arrayToHashKeys(hashes),
}

module.exports = exports = Encrypter;
