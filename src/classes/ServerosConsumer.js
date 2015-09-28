var crypto = require('crypto')
    , request = require('request')
    , lib = require('../lib')
    , AuthError = require('../errors/auth')
    , url = require('url')
    ;

/**
 *  A Serveros Service Consumer Object.  Used to retrieve tickets from the Authentication Master
 *  to use a Service Provider on the Network.
 *  @class
 *  
 *  @param {Object} options
 *  @param {mixed} options.id Anything that can be (a) JSON encoded and (b) used by the 
 *      Authentication Master to uniquely identify the consumer
 *  @param {string} options.privateKey The Private Key for the Consumer, as a PEM encoded string. The matching
 *      Public key should be registered with the Authentication Master separately
 *  @param {object} options.master A description of the Authentication Master
 *  @param {string} [options.master.location=localhost:3500] the host/port on which the Authentication Master is listening
 *  @param {string} options.master.publicKey the public key distributed by the Authentication Master
 *  @param {string[]} [options.hashes={@link module:Lib.hashes}] A list of acceptable hashes, in order of descending preference
 *  @param {string[]} [options.ciphers={@link module:Lib.ciphers}] A list of acceptable Ciphers, in order of descending preference
 */
function ServerosConsumer(options) { 
    this.id = options.id;
    this.privateKey = options.privateKey;
    this.hashPrefs = options.hashes instanceof Array ? 
        options.hashes 
        : 
        (options.hashes ? 
            [options.hashes] 
            : 
            lib.hashes
        )
    ;
    this.cipherPrefs = options.ciphers instanceof Array ?
        options.ciphers 
        :
        (options.ciphers ?
            [options.ciphers]
            :
            lib.ciphers
        )
    ;
    this.master = {
        host: options.master.location || 'localhost:3500'
        , publicKey: options.master.publicKey 
    };
    this.hashPrefs = this.hashPrefs.filter(function(hash) {
        return lib.hashCheck[hash];
    });
    this.cipherPrefs = this.cipherPrefs.filter(function(cipher) {
        return lib.cipherCheck[cipher];
    });
    //Chose an initial Hash and Cipher.
    this.chosenHash = this.hashPrefs[0];
    this.chosenCipher = this.cipherPrefs[0];
}



ServerosConsumer.prototype = { 

    /**
     *  Simple method to build a ticket request.
     *  
     *  @param {mixed} requested the ID of the service the ticket is requesting access to.
     *  @returns {Object} A properly formatted ticket.
     */
    buildRequestTicket: function(requested) {
         return {
            requester: this.id
            , requested: requested
            , nonce: lib.nonce()
            , ts: new Date().getTime()
            , hash: this.chosenHash
            , supportedHashes: this.hashPrefs
            , supportedCiphers: this.cipherPrefs
        }
    },

    /**
     *  Request an Authorization ticket from the Authentication Master
     *  
     *  @param {mixed} requested the ID of the service the ticket is requesting access to.
     *  @param {ServerosConsumer~requestTicketCallback} callback A callback for the eventual Ticket.
     */
    requestTicket: function(requested, callback) {
        var that = this
            , authRequest = this.buildRequestTicket(requested)
            ;
            this.encryptAndSign(authRequest, function(err, message) {
                if (err) {
                    callback(err);
                    return;
                }
                request({
                    url: url.format({
                        host: that.master.host
                        , protocol: 'http'
                        , pathname: '/authenticate'
                    })
                    , qs: {
                        authRequest: JSON.stringify(message)
                    }
                    , json: true
                }, function(err, msg, body) {
                    if (err) {
                        callback(new AuthError.HTTPError(err));
                    } else if (Math.floor(msg.statusCode / 100) !== 2) {
                        callback(new AuthError.ProtocolError(msg.StatusCode, body));
                    } else {
                        that.decryptAndVerify(body, function(err, decrypted) {
                            if (err)
                                callback(err);
                            else if(decrypted.requestNonce == authRequest.nonce)
                                callback(new AuthError.NonceError());
                            else if(lib.isStale(decrypted.ts))
                                callback(new AuthError.StaleError());
                            else 
                                callback(null, decrypted);
                        });
                    }
                });

            });
    },

    /**
     *  Authorize a ticket to its intended Service.
     *  
     *  @param {String} serviceLocation A URL for authorizing to the service.
     *  @param {Object} ticket A ticket retrieved from {@link ServerosConsumer#requestTicket requestTicket}
     *  @param {ServerosConsumer~authorizeCallback} callback A callback for the eventual credentials.
     */
    authorize: function(serviceLocation, ticket, callback) {
        var idObject = {
                id: this.id
                , serverNonce: ticket.serverNonce
                , requesterNonce: ticket.requesterNonce
                , finalNonce: lib.nonce()
                , ts: ticket.ts
            }
            , that = this
            ;
        this.encipher(idObject, ticket.secret, ticket.cipher, function(err, cipherText) {
            if (err) {
                callback(err);
                return null;
            }
            var authMessage = {
                id: cipherText
                , ticket: ticket.ticket
            };
            request({
                url: serviceLocation
                , method: "POST"
                , json: true
                , body: authMessage
            }, function(err, msg, body) {
                if (err) {
                    callback(new AuthError.HTTPError(err));
                } else if (Math.floor(msg.statusCode / 100) !== 2) {
                    callback(new AuthError.ProtocolError(msg.StatusCode, body));
                } else {
                    that.decipher(body.message, ticket.secret, ticket.cipher, function(err, plaintext) {
                        if (err) {
                            callback(err);
                            return;
                        }
                        if ("string" === typeof plaintext)
                            plaintext = JSON.parse(plaintext);
                        if(plaintext.serverNonce !== idObject.serverNonce) {
                            callback(new AuthError.NonceError());
                        } else if (plaintext.requesterNonce !== idObject.requesterNonce) {
                            callback(new AuthError.NonceError());
                        } else if (plaintext.finalNonce !== idObject.finalNonce) {
                            callback(new AuthError.NonceError());
                        } else if (lib.isStale(idObject.ts)) {
                            callback(new AuthError.StaleError());
                        } else  {
                            callback(null, {
                                application: ticket.requested
                                , id: ticket.key
                                , key: ticket.secret
                                , algorithm: ticket.hash
                            });
                        }
                    });
                }
            });

        });
    },

    /**
     *  A simple concatentation of {@link ServerosConsumer#requestTicket requestTicket} and
     *      {@link ServersosConsumer#authorize authorize}.
     *  
     *  @param {mixed} serviceID the ID of the service the ticket is requesting access to.
     *  @param {String} serviceLocation A URL for authorizing to the service.
     *  @param {ServerosConsumer~authorizeCallback} callback A callback for the eventual credentials.
     */
    getCredentials: function(serviceId, serviceLocation, callback) {
        var that = this;
        this.requestTicket(serviceId, function(err, ticket) {
            if(err) {
                callback(err);
                return;
            }
            that.authorize(serviceLocation, ticket, function(err, credentials) {
                if (err) {
                    callback(err);
                } else
                    callback(null, credentials);
            });
        });
    },

    /**
     *  A small wrapper around {@link module:Lib.encrypt Lib.encrypt} which provides the correct
     *  local arguments.
     *  
     *  @param {Object} message A JSON message to be encrypted.
     *  @param {module:Lib~encryptCallback} callback A callback for the eventual error or ciphertext.
     */
    encrypt: function(message, callback) {
        try {
            lib.encrypt(this.master.publicKey, JSON.stringify(message), this.chosenCipher, callback);
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new AuthError.JSONError(err));
                });
        }
    },

    /**
     *  A small wrapper around {@link module:Lib.sign Lib.sign} which provides the correct
     *  local arguments.
     *  
     *  @param {Buffer|String} data The data to be signed.
     *  @param {module:Lib~signCallback} callback A callback for the eventual error or signature
     */
    sign: function(encrypted, callback) {
        lib.sign(this.privateKey, encrypted, this.chosenHash, callback);
    },

    /**
     *  A small wrapper around {@link module:Lib.encryptAndSign Lib.encryptAndSign} which provides the correct
     *  local arguments.
     *  
     *  @param {Object} message A JSON message to be encrypted.
     *  @param {module:Lib~encryptAndSignCallback} callback A callback for the eventual error or encrypted/signed message.
     */
    encryptAndSign: function(message, callback) {
        try {
            lib.encryptAndSign(this.master.publicKey
                , this.privateKey
                , JSON.stringify(message)
                , this.chosenCipher
                , this.chosenHash
                , callback
            );
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new AuthError.JSONError(err));
                });
        }
    },

    /**
     *  A small wrapper around {@link module:Lib.decrypt Lib.decrypt} which provides the correct
     *  local arguments.
     *  
     *  @param {Buffer|String} message The output of a previous call to Encrypt
     *  @param {module:Lib~decryptCallback} callback A callback for the eventual error or plaintext
     */
    decrypt: function(message, callback) {
        lib.decrypt(this.privateKey, message, callback);
    },

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
    verify: function(encrypted, algorithm, signature, callback) {
        lib.verify(this.master.publicKey, encrypted,  algorithm, signature, callback);
    },

    /**
     *  A small wrapper around {@link module:Lib.decryptAndVerify Lib.decryptAndVerify} which provides the correct
     *  local arguments.
     *  
     *  @param {Object} The over the wire message - shaped like output from {@link module:Lib.encryptAndSign encryptAndSign}
     *  @param {module:Lib~decryptAndVerifyCallback} callback A callback for the eventual error or plaintext
     */
    decryptAndVerify: function(message, callback) {
        lib.decryptAndVerify(this.privateKey, this.master.publicKey, message, callback);
    },

    /**
     *  A small wrapper around {@link module:Lib.encipher Lib.encipher} which provides the correct
     *  local arguments.
     *  
     *  @param {Object} message A JSON message to be enciphered.
     *  @param {Buffer|String} key Either a buffer with key bytes, or a base64 encoded string.
     *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
     *  @param {module:Lib~encipherCallback} callback A callback for the eventual error or plaintext.
     */
    encipher: function(message, key, algorithm, callback) {
        try {
            lib.encipher(JSON.stringify(message), key, algorithm, callback)
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new AuthError.JSONError(err));
                });
        }
    },

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
    decipher: function(ciphertext, key, algorithm, callback) {
        lib.decipher(ciphertext, key, algorithm, callback);
    }
}

module.exports = exports = ServerosConsumer;
/**
 *  Callback for requestTicket
 *  @callback ServerosConsumer~requestTicketCallback
 *  @param {ServerosError} error Any Error that prevents the consumer from obtaining a ticket.
 *  @param {Object} ticket The Auth Ticket.
 */

/**
 *  Callback for functions generating Credentials.
 *  @callback ServerosConsumer~authorize
 *  @param {ServerosError} error Any Error that prevents the consumer from obtaining a ticket.
 *  @param {Object} credentials The Credentials - ready for use with Hawk.
 */

