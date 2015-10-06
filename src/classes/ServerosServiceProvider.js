var crypto = require('crypto')
    , AuthError = require('../errors/auth')
    , Encrypter = require('./Encrypter')
    ;

/**
 *  A Serveros Service Provider Object.  Used to validate tickets from the Authentication Master
 *  from a Service Consumer on the Network.
 *  @extends Encrypter
 *  @class
 *  
 *  @param {Object} options
 *  @param {mixed} options.id Anything that can be (a) JSON encoded and (b) used by the 
 *      Authentication Master to uniquely identify the Service Provider
 *  @param {string} options.privateKey The Private Key for the Service Provider, as a PEM encoded string. The matching
 *      Public Key should be registered with the Authentication Master separately
 *  @param {object} options.master A description of the Authentication Master
 *  @param {string} options.master.publicKey the public key distributed by the Authentication Master
 *  @param {string[]} [options.hashes={@link module:Lib.hashes}] A list of acceptable hashes, in order of descending preference
 *  @param {string[]} [options.ciphers={@link module:Lib.ciphers}] A list of acceptable Ciphers, in order of descending preference
 */
function ServerosServiceProvider(options) {
    var that = this;
    this.id = options.id;
    this.privateKey = options.privateKey;
    if (!!(options.hashes)) {
        this.hashPrefs = options.hashes instanceof Array ? options.hashes : [options.hashes];
        this.hashPrefs = this.hashPrefs.filter(function(hash) {
            return that.hashCheck[hash];
        });
    }
    if (!!(options.ciphers)) {
        this.cipherPrefs = options.ciphers instanceof Array ? options.ciphers : [options.ciphers];
        this.cipherPrefs = this.cipherPrefs.filter(function(cipher) {
            return that.cipherCheck[cipher];
        });
    }
    this.master = {
        publicKey: options.master.publicKey 
    };
    //Chose an initial Hash and Cipher.
    this.chosenHash = this.hashPrefs[0];
    this.chosenCipher = this.cipherPrefs[0];
}


ServerosServiceProvider.prototype = Object.create(Encrypter.prototype);

Object.defineProperty(ServerosServiceProvider.prototype, 'constructor', {
    enumerable: false
    , value: ServerosServiceProvider
});


/**
 *  Validate an incoming Greeting.
 *  
 *  @param {Object} greeting The over the wire Greeting from a Service Consumer.
 *  @param {ServerosServiceProvider~validateCallback} A callback for the eventual credentials.
 */
ServerosServiceProvider.prototype.validate = function(greeting, callback) {
    var that = this;
    this.idecrypt(greeting.ticket.message, function(err, ticket) {
        if(err) {
            callback(err);
            return;
        }
        that.iverify(greeting.ticket.message, ticket.hash, greeting.ticket.signature, function(err, verified) {
            if (err) {
                if (callback) callback(err);
                return;
            }
            that.idecipher(greeting.id, ticket.oneTimeCredentials.key, ticket.oneTimeCredentials.iv, ticket.cipher, function(err, plaintext) {
                if (err) {
                    callback(err);
                    return;
                }
                var id = JSON.parse(plaintext);
                if(id.serverNonce !== ticket.serverNonce) 
                    callback(new AuthError.NonceError());
                else if (id.requesterNonce !== ticket.requesterNonce)
                    callback(new AuthError.NonceError());
                else if (that.isStale(ticket.ts))
                    callback(new AuthError.StaleError());
                else 
                    /**
                     *  @callback ServerosServiceProvider~validateCallback
                     *  @param {ServerosError} err Any error which prevents validation.
                     *  @param {object} credentials Successfully verified credentials - which should 
                     *      be responded to in the affirmative in the future,
                     *      until they're no longer valid.
                     */
                    callback(null, {
                        id: ticket.id
                        , secret: ticket.secret
                        , authData: ticket.authData
                        , requester: ticket.requester
                        , hash: ticket.hash
                        , cipher: ticket.cipher
                        , expires: ticket.expires
                        , oneTimeCredentials: ticket.oneTimeCredentials
                        , nonces: {
                            server: id.serverNonce
                            , requester: id.requesterNonce
                            , final: id.finalNonce
                            , iv: id.iv
                        }
                    });
            });
        });
    });
};

/**
 *  Generate
 *  @param {ServerosServiceProvider~validatorCallback} onSuccessfulGreeting callback to be called anytime
 *      an incoming greeting is successful.
 *  @returns {function} An Express Endpoint.
 */
ServerosServiceProvider.prototype.expressValidator = function(onSuccessfulGreeting) {
    var that = this;
    return function(req, res, next) {
        var greeting = req.body instanceof String ? JSON.parse(req.body) : req.body;
        that.validate(greeting, function(err, authorized) {
            if (err) {
                res.status(err.statusCode).json(err.prepResponseBody());
            } else {
                try {

                    /**
                     *  A callback for 
                     *  @callback ServerosServiceProvider~validatorCallback
                     *  @param {object} credentials Successfully verified credentials - which should
                     *      be responded to in the affirmative in the future, until they're no 
                     *      longer valid.
                     */
                    if (onSuccessfulGreeting) onSuccessfulGreeting(authorized);
                    that.iencipher( {
                        serverNonce: authorized.nonces.server
                        , requesterNonce: authorized.nonces.requester
                        , finalNonce: authorized.nonces.final
                        , ts: new Date().getTime()
                    }, authorized.oneTimeCredentials.key, authorized.nonces.iv, authorized.cipher, function(err, ciphertext) {
                        if (err) {
                            res.status(err.statusCode).json(err.prepResponseBody());
                        }
                        res.json({message:ciphertext});
                    });
                    
                } catch (err) {
                    res.status(500).json({'err': err});
                }
            }
        });
    }
};

/**
 *  A small wrapper around {@link module:Lib.encrypt Lib.encrypt} which provides the correct
 *  local arguments.
 *  
 *  @param {Object} message A JSON message to be encrypted.
 *  @param {module:Lib~encryptCallback} callback A callback for the eventual error or ciphertext.
 */
ServerosServiceProvider.prototype.iencrypt = function(message, callback) {
    this.encrypt(this.master.publicKey, JSON.stringify(message), this.cipherPrefs[this.cipherIndex], callback);
};

/**
 *  A small wrapper around {@link module:Lib.sign Lib.sign} which provides the correct
 *  local arguments.
 *  
 *  @param {Buffer|String} data The data to be signed.
 *  @param {module:Lib~signCallback} callback A callback for the eventual error or signature
 */
ServerosServiceProvider.prototype.isign = function(encrypted, callback) {
    this.sign(this.privateKey, encrypted, this.hashPrefs[this.hashIndex], callback);
};

/**
 *  A small wrapper around {@link module:Lib.encryptAndSign Lib.encryptAndSign} which provides the correct
 *  local arguments.
 *  
 *  @param {Object} message A JSON message to be encrypted.
 *  @param {module:Lib~encryptAndSignCallback} callback A callback for the eventual error or encrypted/signed message.
 */
ServerosServiceProvider.prototype.iencryptAndSign = function(message, callback) {
    try {
        this.encryptAndSign(this.master.publicKey
            , this.privateKey
            , JSON.stringify(message)
            , this.chosenCipher
            , this.hashPrefs[this.hashIndex]
            , callback
        );
    } catch (err) {
        if (callback)
            process.nextTick(function() {
                callback(new AuthError.JSONError(err));
            });
    }
};

/**
 *  A small wrapper around {@link module:Lib.decrypt Lib.decrypt} which provides the correct
 *  local arguments.
 *  
 *  @param {Buffer|String} message The output of a previous call to Encrypt
 *  @param {module:Lib~decryptCallback} callback A callback for the eventual error or plaintext
 */
ServerosServiceProvider.prototype.idecrypt = function(message, callback) {
    this.decrypt(this.privateKey, message, callback);
};

/**
 *  A small wrapper around {@link module:Lib.verify Lib.verify} which provides the correct
 *  local arguments.
 *  
 *  @param {Buffer|String} data The previously signed data.
 *  @param {String} algorithm The Hash algorithm to use whilst calculating the HMAC
 *  @param {Buffer|String} signature The previously generated Signature - as a buffer or base64
 *      encoded String.
 *  @param {module:Lib~verifyCallback} callback A callback for the eventual error or verification Status
 */
ServerosServiceProvider.prototype.iverify = function(encrypted, algorithm, signature, callback) {
    this.verify(this.master.publicKey, encrypted,  algorithm, signature, callback);
}; 

/**
 *  A small wrapper around {@link module:Lib.decryptAndVerify Lib.decryptAndVerify} which provides the correct
 *  local arguments.
 *  
 *  @param {Object} The over the wire message - shaped like output from {@link module:Lib.encryptAndSign encryptAndSign}
 *  @param {module:Lib~decryptAndVerifyCallback} callback A callback for the eventual error or plaintext
 */
ServerosServiceProvider.prototype.idecryptAndVerify = function(message, callback) {
    this.decryptAndVerify(this.privateKey, this.master.publicKey, message, callback);
};

/**
 *  A small wrapper around {@link module:Lib.encipher Lib.encipher} which provides the correct
 *  local arguments.
 *  
 *  @param {Object} message A JSON message to be enciphered.
 *  @param {Buffer|String} key Either a buffer with key bytes, or a base64 encoded string.
 *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
 *  @param {module:Lib~encipherCallback} callback A callback for the eventual error or plaintext.
 */
ServerosServiceProvider.prototype.iencipher = function(message, key, iv, algorithm, callback) {
    try {
        this.encipher(JSON.stringify(message), key, iv, algorithm, callback)
    } catch (err) {
        if (callback)
            process.nextTick(function() {
                callback(new AuthError.JSONError(err));
            });
    }
};

/**
 *  A simple wrapper around {@link module:Lib.decipher Lib.decipher} which provides the correct
 *  local arguments.
 *  
 *  @param {Buffer|String} ciphertext Either a buffer with cipher bytes, or a base64 encoded string.
 *  @param {Buffer|String} key Either a buffer with key bytes, or a base64 encoded string.
 *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
 *  @param {module:Lib~decipherCallback} callback A callback for the eventual error or plaintext.
 *  @static
 */
ServerosServiceProvider.prototype.idecipher = function(ciphertext, key, iv, algorithm, callback) {
    this.decipher(ciphertext, key, iv, algorithm, callback);
};

module.exports = exports = ServerosServiceProvider;
