var crypto = require('crypto')
    , request = require('request')
    , Encrypter = require('./Encrypter')
    , AuthError = require('../errors/auth')
    , url = require('url')
    ;

/**
 *  A Serveros Service Consumer Object.  Used to retrieve tickets from the Authentication Master
 *  to use a Service Provider on the Network.
 *  @extends Serveros.Encrypter
 *  @class Serveros.ServerosConsumer
 *
 *  @param {Object} options
 *  @param {mixed} options.id Anything that can be (a) JSON encoded and (b) used by the
 *      Authentication Master to uniquely identify the consumer
 *  @param {string} options.privateKey The Private Key for the Consumer, as a PEM encoded string. The matching
 *      Public key should be registered with the Authentication Master separately
 *  @param {object} options.master A description of the Authentication Master
 *  @param {string} [options.master.location=localhost:3500] the host/port on which the Authentication Master is listening
 *  @param {string} options.master.publicKey the public key distributed by the Authentication Master
 *  @param {string[]} [options.hashes={@link Serveros.Encrypter.hashes}] A list of acceptable hashes, in order of descending preference
 *  @param {string[]} [options.ciphers={@link Serveros.Encrypter.ciphers}] A list of acceptable Ciphers, in order of descending preference
 */
function ServerosConsumer(options) {
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
        host: options.master.location || 'localhost:3500'
        , publicKey: options.master.publicKey
    };
    //Chose an initial Hash and Cipher.
    this.chosenHash = this.hashPrefs[0];
    this.chosenCipher = this.cipherPrefs[0];
}

ServerosConsumer.prototype = Object.create(Encrypter.prototype);

Object.defineProperty(ServerosConsumer.prototype, 'constructor', {
    enumerable: false
    , value: ServerosConsumer
});


/**
 *  Simple method to build a ticket request.
 *
 *  @param {mixed} requested the ID of the service the ticket is requesting access to.
 *  @returns {Object} A properly formatted ticket.
 */
ServerosConsumer.prototype.buildRequestTicket = function(requested) {
     return {
        requester: this.id
        , requested: requested
        , nonce: this.nonce()
        , ts: new Date().getTime()
        , hash: this.chosenHash
        , supportedHashes: this.hashPrefs
        , supportedCiphers: this.cipherPrefs
    }
};

/**
 *  Request an Authorization ticket from the Authentication Master
 *
 *  @param {mixed} requested the ID of the service the ticket is requesting access to.
 *  @param {Serveros.ServerosConsumer~requestTicketCallback} callback A callback for the eventual Ticket.
 */
ServerosConsumer.prototype.requestTicket = function(requested, callback) {
    var that = this
        , authRequest = this.buildRequestTicket(requested)
        ;
        this.iencryptAndSign(authRequest, function(err, message) {
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
                    if (msg.statusCode == 409) {
                        for(var i = 0; i < that.cipherPrefs.length; i++) {
                            if (body.additionalInformation.supported.indexOf(that.cipherPrefs[i]) != -1) {
                                that.chosenCipher = that.cipherPrefs[i];
                                that.requestTicket(requested, callback);
                                return;
                            } //Check if the Master supports it.
                        } //For each cipher I support
                    } //unsupportedCipher.
                    else if (msg.statusCode == 490) {
                        for(var i = 0; i < that.hashPrefs.length; i++) {
                            if (body.additionalInformation.supported.indexOf(that.hashPrefs[i]) != -1) {
                                that.chosenHash = that.hashPrefs[i];
                                that.requestTicket(requested, callback);
                                return;
                            } //Check if the Master supports it.
                        } //For each hash I support
                    } //unsupportedHash
                    callback(new AuthError.ProtocolError(msg.StatusCode, body));
                } else {
                    that.idecryptAndVerify(body, function(err, decrypted) {
                        if (err)
                            callback(err);
                        else if(decrypted.requesterNonce != authRequest.nonce)
                            callback(new AuthError.NonceError());
                        else if(that.isStale(decrypted.ts))
                            callback(new AuthError.StaleError());
                        else
                            /**
                             *  Callback for requestTicket
                             *  @callback Serveros.ServerosConsumer~requestTicketCallback
                             *  @param {Error.ServerosError} error Any Error that prevents the consumer from obtaining a ticket.
                             *  @param {Object} ticket The Auth Ticket.
                             */
                            callback(null, decrypted);
                    });
                }
            });

        });
};

/**
 *  Authorize a ticket to its intended Service.
 *
 *  @param {String} serviceLocation A URL for authorizing to the service.
 *  @param {Object} ticket A ticket retrieved from {@link Serveros.ServerosConsumer#requestTicket requestTicket}
 *  @param {Serveros.ServerosConsumer~authorizeCallback} callback A callback for the eventual credentials.
 */
ServerosConsumer.prototype.authorize = function(serviceLocation, ticket, callback) {
    var that = this;
    crypto.randomBytes(new Buffer(ticket.oneTimeCredentials.iv, 'base64').length, function(err, returnIV) {
        var idObject = {
                id: that.id
                , serverNonce: ticket.serverNonce
                , requesterNonce: ticket.requesterNonce
                , finalNonce: that.nonce()
                , iv: returnIV.toString('base64')
                , ts: new Date().getTime()
            }
            ;
        that.iencipher(idObject
                , ticket.oneTimeCredentials.key
                , ticket.oneTimeCredentials.iv
                , ticket.oneTimeCredentials.cipher
                , function(err, cipherText) {
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
                    that.idecipher(body.message
                            , ticket.oneTimeCredentials.key
                            , returnIV
                            , ticket.oneTimeCredentials.cipher
                            , function(err, plaintext) {
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
                        } else if (that.isStale(idObject.ts)) {
                            callback(new AuthError.StaleError());
                        } else  {
                            callback(null, {
                                application: ticket.requested
                                , id: ticket.id
                                , key: ticket.secret
                                , algorithm: ticket.hash
                                , expires: ticket.expires
                            });
                        }
                    });
                }
            });

        });
    });
};

/**
 *  A simple concatentation of {@link Serveros.ServerosConsumer#requestTicket requestTicket} and
 *      {@link Serveros.ServersosConsumer#authorize authorize}.
 *
 *  @param {mixed} serviceID the ID of the service the ticket is requesting access to.
 *  @param {String} serviceLocation A URL for authorizing to the service.
 *  @param {Serveros.ServerosConsumer~authorizeCallback} callback A callback for the eventual credentials.
 */
ServerosConsumer.prototype.getCredentials = function(serviceId, serviceLocation, callback) {
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
                /**
                 *  Callback for functions generating Credentials.
                 *  @callback Serveros.ServerosConsumer~authorize
                 *  @param {Error.ServerosError} error Any Error that prevents the consumer from obtaining a ticket.
                 *  @param {Object} credentials The Credentials - ready for use with Hawk.
                 */
                callback(null, credentials);
        });
    });
};

/**
 *  A small wrapper around {@link Serveros.Encrypter.encrypt Lib.encrypt} which provides the correct
 *  local arguments.
 *
 *  @param {Object} message A JSON message to be encrypted.
 *  @param {Serveros.Encrypter~encryptCallback} callback A callback for the eventual error or ciphertext.
 */
ServerosConsumer.prototype.iencrypt = function(message, callback) {
    try {
        this.encrypt(this.master.publicKey, JSON.stringify(message), this.chosenCipher, callback);
    } catch (err) {
        if (callback)
            process.nextTick(function() {
                callback(new AuthError.JSONError(err));
            });
    }
};

/**
 *  A small wrapper around {@link Serveros.Encrypter.sign Lib.sign} which provides the correct
 *  local arguments.
 *
 *  @param {Buffer|String} data The data to be signed.
 *  @param {Serveros.Encrypter~signCallback} callback A callback for the eventual error or signature
 */
ServerosConsumer.prototype.isign = function(encrypted, callback) {
    this.sign(this.privateKey, encrypted, this.chosenHash, callback);
};

/**
 *  A small wrapper around {@link Serveros.Encrypter.encryptAndSign Lib.encryptAndSign} which provides the correct
 *  local arguments.
 *
 *  @param {Object} message A JSON message to be encrypted.
 *  @param {Serveros.Encrypter~encryptAndSignCallback} callback A callback for the eventual error or encrypted/signed message.
 */
ServerosConsumer.prototype.iencryptAndSign = function(message, callback) {
    try {
        this.encryptAndSign(this.master.publicKey
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
};

/**
 *  A small wrapper around {@link Serveros.Encrypter.decrypt Lib.decrypt} which provides the correct
 *  local arguments.
 *
 *  @param {Buffer|String} message The output of a previous call to Encrypt
 *  @param {Serveros.Encrypter~decryptCallback} callback A callback for the eventual error or plaintext
 */
ServerosConsumer.prototype.idecrypt = function(message, callback) {
    this.decrypt(this.privateKey, message, callback);
};

/**
 *  A small wrapper around {@link Serveros.Encrypter.verify Lib.verify} which provides the correct
 *  local arguments.
 *
 *  @param {Buffer|String} data The previously signed data.
 *  @param {String} algorithm The Hash algorithm to use whilst calculating the HMAC
 *  @param {Buffer|String} signature The previously generated Signature - as a buffer or base64
 *      encoded String.
 *  @param {Serveros.Encrypter~verifyCallback} callback A callback for the eventual error or verification Status
 */
ServerosConsumer.prototype.iverify = function(encrypted, algorithm, signature, callback) {
    this.verify(this.master.publicKey, encrypted,  algorithm, signature, callback);
};

/**
 *  A small wrapper around {@link Serveros.Encrypter.decryptAndVerify Lib.decryptAndVerify} which provides the correct
 *  local arguments.
 *
 *  @param {Object} The over the wire message - shaped like output from {@link Serveros.Encrypter.encryptAndSign encryptAndSign}
 *  @param {Serveros.Encrypter~decryptAndVerifyCallback} callback A callback for the eventual error or plaintext
 */
ServerosConsumer.prototype.idecryptAndVerify = function(message, callback) {
    this.decryptAndVerify(this.privateKey, this.master.publicKey, message, callback);
};

/**
 *  A small wrapper around {@link Serveros.Encrypter.encipher Lib.encipher} which provides the correct
 *  local arguments.
 *
 *  @param {Object} message A JSON message to be enciphered.
 *  @param {Buffer|String} key Either a buffer with key bytes, or a base64 encoded string.
 *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
 *  @param {Serveros.Encrypter~encipherCallback} callback A callback for the eventual error or plaintext.
 */
ServerosConsumer.prototype.iencipher = function(message, key, iv, algorithm, callback) {
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
 *  A simple wrapper around {@link Serveros.Encrypter.decipher Lib.decipher} which provides the correct
 *  local arguments.
 *
 *  @param {Buffer|String} ciphertext Either a buffer with cipher bytes, or a base64 encoded string.
 *  @param {Buffer|String} key Either a buffer with key bytes, or a base64 encoded string.
 *  @param {Buffer|String} algorithm The cipher algorithm to use while deciphering.
 *  @param {Serveros.Encrypter~decipherCallback} callback A callback for the eventual error or plaintext.
 *  @static
 */
ServerosConsumer.prototype.idecipher = function(ciphertext, key, iv, algorithm, callback) {
    this.decipher(ciphertext, key, iv, algorithm, callback);
};

module.exports = exports = ServerosConsumer;

