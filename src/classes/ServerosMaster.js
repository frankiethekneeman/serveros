var crypto = require('crypto')
    , lib = require('../lib')
    , MasterError = require('../errors/master')
    , AuthError = require('../errors/auth')
    ;

/**
 *  A Serveros Authentication Master.
 *  @class
 *  
 *  @param {Object} options
 *  @param {string} options.privateKey The Private Key for the Authentication Master, as a PEM encoded string. The matching
 *      Public Key should be distrubuted to Consumers and Service Providers alike.
 *  @param {ServerosMaster~publicKeyFunction} options.publicKeyFunction A function by which the Authentication 
 *      Master can ask for Public Keys.
 *  @param {string[]} [options.hashes={@link module:Lib.hashes}] A list of acceptable hashes, in order of descending preference
 *  @param {string[]} [options.ciphers={@link module:Lib.ciphers}] A list of acceptable Ciphers, in order of descending preference
 */
function ServerosMaster(options) { //myPrivateKey, publicKeyFunction, hashArr, cipherArr) {
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
    /**
     *  A function to ask for public Keys.
     *  @callback ServerosMaster~publicKeyFunction
     *  
     *  @param {mixed} id The ID of the application whose public key is needed.
     *  @param {mixed} for The ID of the service this application wants to use.
     *  @param {ServerosMaster~publicKeyResponse} callback a callback for the key data.
     */
    this.publicKeyFunction = options.publicKeyFunction;
    this.hashPrefs = this.hashPrefs.filter(function(hash) {
        return lib.hashCheck[hash];
    });
    this.cipherPrefs = this.cipherPrefs.filter(function(cipher) {
        return lib.cipherCheck[cipher];
    });
}



ServerosMaster.prototype = { 
    /**
     *  Authenticate a consumer, and give it a ticket.
     *  
     *  @param {object} authentication message from over the wire.
     *  @param {ServerosMaster~authenticateCallback} callback a callback for the authentication intormation.
     */
    authenticate: function(authenticationMessage, callback) {
        var that = this;
        this.decrypt(authenticationMessage.message, function(err, decrypted) {
            if(err) {
                callback(err);
                return;
            } 
            if(lib.isStale(decrypted.ts)) {
                callback(new AuthError.StaleError());
                return;
            }
            /**
             *  A callback for the {@link SeverosMaster.publicKeyFunction}
             *  @callback ServerosMaster~publicKeyResponse
             *  
             *  @param {object} data App Data.
             *  @param {mixed} data.id The id of the application.
             *  @param {string[]} [data.hashes={@link module:Lib.hashes}] A list of acceptable hashes, in order of descending preference
             *  @param {string[]} [data.ciphers={@link module:Lib.ciphers}] A list of acceptable Ciphers, in order of descending preference
             *  @param {integer} data.keysLast The amount of time, in milliseconds, this application wants to honor keys.
             *  @param {mixed} data.authData Any additional data about the application that should be passed on to the service.
             */
            try {
                that.publicKeyFunction(decrypted.requester, decrypted.requested, function(requester) {
                    if (!requester) {
                        callback(new MasterError.ApplicationResolutionError("requester"));
                    }
                    that.verify(requester.publicKey
                            , authenticationMessage.message
                            , decrypted.hash
                            , authenticationMessage.signature
                            , function(err, verified) {
                        if (err) {
                            callback(err);
                            return;
                        }
                        that.getTicket(decrypted, requester, function(err, ticket) {
                            if (err) {
                                callback(err);
                                return;
                            }
                            that.prepResponse(ticket, requester, function(err, response) {
                                if (err)
                                    callback(err);
                                else
                                    /**
                                     *  Passing back the authentcation information.
                                     *  @callback ServerosMaster~authenticateCallback
                                     *  
                                     *  @param {ServerosError} err any error preventing authentication.
                                     *  @param {object} response
                                     */
                                    callback(null, response);
                            });
                        });
                    });
                });
            } catch (err) {
                callback(new MasterError.PublicKeyFunctionError(err));
            }
        });
    },

    /**
     *  Build the ticket for response.
     *  
     *  @param {Object} request The decrypted request from over the wire.
     *  @param {Object} requested The Service being requested.
     *  @param {Object} requester The Consumer requesting access.
     *  @param {ServerosMaster~buildTicketCallback} callback a callback for the ticket.
     */
    buildTicket: function(request, requested, requester, callback) {
        var that = this;
        lib.shortUseKey(function(err, key) {
            if (err) {
                callback(err);
                return;
            }
            lib.shortUseKey(function(err, secret) {
                if (err) {
                    callback(err);
                    return;
                }
                var ticketData = {
                    "requester": request.requester
                    , "requested": requested.id
                    , "serverNonce": lib.nonce()
                    , "requesterNonce": request.nonce
                    , "key": key.toString('base64')
                    , "secret": secret.toString('base64')
                    , "ts": new Date().getTime()
                    , cipher: that.chooseCipher(requested.ciphers)
                    , hash: that.chooseHash(requested.hashes)
                    , expires: request.ts + requested.keysLast
                    , authData: requester.authData
                }
                /**
                 *  Return ticket information.
                 *  @callback ServerosMaster~buildTicketCallback
                 *  
                 *  @param {ServerosError} error any error that prevents ticket generation.
                 *  @param {object} ticketData the ticket.
                 *  @param {object} ticketData.requester The consumer asking for access.
                 *  @param {object} ticketData.requested The service for which access is needed.
                 *  @param {mixed} ticketData.serverNonce A new nonce.
                 *  @param {mixed} ticketData.requesterNonce the nonce from the request.
                 *  @param {string} ticketData.key A Key for consumer/service communication.
                 *  @param {string} ticketData.secret A secret for consumer/service communication.
                 *  @param {number} ticketData.ts The timestamp of ticket creation, in millis since the epoch.
                 *  @param {string} ticketData.cipher The name of the selected Cipher algorithm.
                 *  @param {string} ticketData.hash the name of the selected Hash algorithm.
                 *  @param {number} ticketData.expires the expiration date of the keys contained herein.
                 *  @param {mixed} ticketData.authData Authentication/Authorization data from the master application.
                 */
                callback(null, ticketData);
            });
        });
    },
    /**
     *  Get a ticket, encrypted and signed.
     *  
     *  @param {Object} request From the wire, decrypted.
     *  @param {Object} requester The application making the request.
     *  @param {ServerosMaster~getTicketCallback} callback A callback for the eventual ticket.
     */
    getTicket: function(request, requester, callback) {
        var that = this;
        this.publicKeyFunction(request.requested, null, function(requested) {
            that.buildTicket(request, requested, requester, function(err, ticket) {
                if (err) {
                    callback(err);
                    return;
                }
                that.encryptAndSign(requested.publicKey, ticket, ticket.cipher, ticket.hash, function(err, message) {
                    if (err)
                        callback(err);
                    else
                        /**
                         *  Return the ticket.
                         *  @callback ServerosMaster~getTicketCallback
                         *  
                         *  @param {ServerosError} err any error to prevent ticket generation.
                         *  @param {object} ticket
                         *  @param {object} ticket.raw The raw ticket.
                         *  @param {object} ticket.ready The ticket, ecrypted and signed.
                         */
                        callback(null, { raw: ticket
                            , ready: message
                        });
                });
            });
        });
    },

    /**
     *  Prep a response to the server.
     *  
     *  @param {Object} ticket A ticket from {@link ServerosMaster.getTicket}
     *  @param {Object} requester The application requesting the ticket
     *  @param {ServerosMaster~prepReponseCallback} callback a callback for the signed, encrypted response.
     */
    prepResponse: function(ticket, requester, callback) {
        var that = this
            , response = {
                "requester": ticket.raw.requester
                , "requested": ticket.raw.requested
                , "serverNonce": ticket.raw.serverNonce
                , "requesterNonce": ticket.raw.requesterNonce
                , "key": ticket.raw.key
                , "secret": ticket.raw.secret
                , "ts": ticket.raw.ts
                , hash: this.chooseHash(requester.hashes)
                , cipher: ticket.raw.cipher
                , expires: ticket.raw.expires
                , "ticket": ticket.ready
            };
        this.encryptAndSign(requester.publicKey, response, response.cipher, response.hash, function(err, encrypted) {
            if (err)
                callback(err);
            else 
                /**
                 *  Returns the desired response, encrypted and signed.
                 *  @callback ServerosMaster~prepResponseCallback
                 *  
                 *  @param {ServerosError} err Any error
                 *  @param {Object} response The signed and encrypted response.
                 */
                callback(null, encrypted);
        });
    },

    /**
     *  Add an authentication endpoint (GET /authenticate) to an Express Application.
     *  
     *  @param {ExpressApplication} application an Express application.
     */
    addAuthenticationEndpoint: function(application) {
        var that = this;
        application.get('/authenticate', function(req, res, next) {
            var authRequest = JSON.parse(req.query.authRequest);
            that.authenticate(authRequest, function(err, response) {
                if (err) 
                    res.status(err.statusCode).json(err.prepResponseBody());
                else 
                    res.json(response);
            });
        });
    },

    /**
     *  Choose the best hash.
     *  
     *  @param {string[]} supported A list of desired Hashes.
     *  @todo make this do something interesting.
     */
    chooseHash: function(supported) {
        return this.hashPrefs[0];
    },

    /**
     *  Choose the best ciphers.
     *  
     *  @param {string[]} supported A list of desired Ciphers.
     *  @todo make this do something interesting.
     */
    chooseCipher: function(supported) {
        return this.cipherPrefs[0];
    },

    /**
     *  A simple wrapper around {@link module:Lib.decrypt Lib.decrypt}
     *  
     *  @param {Buffer|String} data The output of a previous call to Encrypt
     *  @param {module:Lib~decryptCallback} callback A callback for the eventual error or plaintext
     */
    decrypt: function(message, callback) {
        lib.decrypt(this.privateKey, message, callback);
    },

    /**
     *  A simple wrapper around {@link module:Lib.encrypt Lib.decrypt}
     *  
     *  @param {Buffer|String} publicKey A PEM Encoded RSA Key (Public Key)
     *  @param {Object} message A Json Object to be encrypted.
     *  @param {String} cipher The cipher algorithm to use while enciphering.
     *  @param {module:Lib~encryptCallback} callback A callback for the eventual error or ciphertext.
     */
    encrypt: function(publicKey, message, cipher, callback) {
        lib.encrypt(publicKey, JSON.stringify(message), cipher, callback);
    },

    /**
     *  A simple wrapper around {@link module:Lib.sign Lib.decrypt}
     *  
     *  @param {Buffer|String} data The data to be signed.
     *  @param {String} hash The Hash algorithm to use whilst calculating the HMAC
     *  @param {module:Lib~signCallback} callback A callback for the eventual error or signature
     */
    sign: function(data, hash, callback) {
        lib.sign(this.privateKey, data, hash, callback);
    },

    /**
     *  A simple wrapper around {@link module:Lib.verify Lib.decrypt}
     *  
     *  @param {Buffer|String} rsaKey A PEM Encoded RSA Key (Public Key)
     *  @param {Buffer|String} data The previously signed data.
     *  @param {String} algorithm The Hash algorithm to use whilst calculating the HMAC
     *  @param {Buffer|String} signature The previously generated Signature - as a buffer or base64
     *      encoded String.
     *  @param {module:Lib~verifyCallback} callback A callback for the eventual error or verification Status
     */
    verify: function(rsaKey, data, algorithm, signature, callback) {
        lib.verify(rsaKey, data,  algorithm, signature, callback);
    },

    /**
     *  A small wrapper around {@link module:Lib.encryptAndSign Lib.encryptAndSign} which provides the correct
     *  local arguments.
     *  
     *  @param {Buffer|String} publicKey A PEM Encoded RSA Key (Public Key)
     *  @param {Object} message A JSON message to be encrypted.
     *  @param {String} cipher The cipher algorithm to use while enciphering.
     *  @param {String} hash The Hash algorithm to use whilst calculating the HMAC
     *  @param {module:Lib~encryptAndSignCallback} callback A callback for the eventual error or encrypted/signed message.
     */
    encryptAndSign: function(rsaKey, message, cipher, hash, callback) {
        try {
            lib.encryptAndSign(rsaKey
                , this.privateKey
                , JSON.stringify(message)
                , cipher
                , hash
                , callback
            );
        } catch (err) {
            if (callback)
                process.nextTick(function() {
                    callback(new AuthError.JSONError(err));
                });
        }
    }
}

module.exports = exports = ServerosMaster;

