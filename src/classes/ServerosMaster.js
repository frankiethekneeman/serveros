var crypto = require('crypto')
    , Encrypter = require('./Encrypter')
    , MasterError = require('../errors/master')
    , AuthError = require('../errors/auth')
    ;

/**
 *  A Serveros Authentication Master.
 *  @extends Serveros.Encrypter
 *  @class Serveros.ServerosMaster
 *
 *  @param {Object} options
 *  @param {string} options.privateKey The Private Key for the Authentication Master, as a PEM encoded string. The matching
 *      Public Key should be distrubuted to Consumers and Service Providers alike.
 *  @param {Serveros.ServerosMaster~publicKeyFunction} options.publicKeyFunction A function by which the Authentication
 *      Master can ask for Public Keys.
 *  @param {string[]} [options.hashes={@link Serveros.Encrypter~hashes}] A list of acceptable hashes, in order of descending preference
 *  @param {string[]} [options.ciphers={@link Serveros.Encrypter~ciphers}] A list of acceptable Ciphers, in order of descending preference
 */
function ServerosMaster(options) { //myPrivateKey, publicKeyFunction, hashArr, cipherArr) {
    var that = this;
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

    /**
     *  A function to ask for public Keys.
     *  @callback Serveros.ServerosMaster~publicKeyFunction
     *
     *  @param {mixed} id The ID of the application whose public key is needed.
     *  @param {mixed} for The ID of the service this application wants to use.
     *  @param {Serveros.ServerosMaster~publicKeyResponse} callback a callback for the key data.
     */
    this.publicKeyFunction = options.publicKeyFunction;
}

ServerosMaster.prototype = Object.create(Encrypter.prototype);

Object.defineProperty(ServerosMaster.prototype, 'constructor', {
    enumerable: false
    , value: ServerosMaster
});

/**
 *  Authenticate a consumer, and give it a ticket.
 *
 *  @param {object} authentication message from over the wire.
 *  @param {Serveros.ServerosMaster~authenticateCallback} callback a callback for the authentication intormation.
 */
ServerosMaster.prototype.authenticate = function(authenticationMessage, callback) {
    var that = this;
    this.idecrypt(authenticationMessage.message, function(err, decrypted) {
        if(err) {
            callback(err);
            return;
        }
        if(that.isStale(decrypted.ts)) {
            callback(new AuthError.StaleError());
            return;
        }

        /**
         *  A callback for the {@link SeverosMaster.publicKeyFunction}
         *  @callback Serveros.ServerosMaster~publicKeyResponse
         *
         *  @param {object} data App Data.
         *  @param {mixed} data.id The id of the application.
         *  @param {string[]} [data.hashes={@link Serveros.Encrypter~hashes}] A list of acceptable hashes, in order of descending preference
         *  @param {string[]} [data.ciphers={@link Serveros.Encrypter~ciphers}] A list of acceptable Ciphers, in order of descending preference
         *  @param {integer} data.keysLast The amount of time, in milliseconds, this application wants to honor keys.
         *  @param {mixed} data.authData Any additional data about the application that should be passed on to the service.
         */
        try {
            that.publicKeyFunction(decrypted.requester, decrypted.requested, function(requester) {
                if (!requester) {
                    callback(new MasterError.ApplicationResolutionError("requester"));
                }
                that.iverify(requester.publicKey
                        , authenticationMessage.message
                        , decrypted.hash
                        , authenticationMessage.signature
                        , function(err, verified) {
                    if (err || !verified) {
                        callback(err || "Verification Returned False");
                        return;
                    }
                    that.getTicket(decrypted, requester, decrypted.chosen, function(err, ticket) {
                        if (err) {
                            callback(err);
                            return;
                        }
                        that.prepResponse(ticket, requester, verified.chosen, decrypted.chosen, function(err, response) {
                            if (err)
                                callback(err);
                            else
                                /**
                                 *  Passing back the authentcation information.
                                 *  @callback Serveros.ServerosMaster~authenticateCallback
                                 *
                                 *  @param {Error.ServerosError} err any error preventing authentication.
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
};

/**
 *  Build the ticket for response.
 *
 *  @param {Object} request The decrypted request from over the wire.
 *  @param {Object} requested The Service being requested.
 *  @param {Object} requester The Consumer requesting access.
 *  @param {Serveros.ServerosMaster~buildTicketCallback} callback a callback for the ticket.
 *  @todo This function needs to be rewritten to support more interesting credentials.  Specifically,
 *      these should include a key and IV for a cipher supported by both the requested and the requester,
 *      as well as an id and key suitable for use with HAWK, the chosen method for continued
 *      authentication between Consumer and Provider.
 */
ServerosMaster.prototype.buildTicket = function(request, requested, requester, callback) {
    var that = this
        , cipher = this.choose(requester.ciphers, requested.ciphers);
    ;
    this.getOneTimeCredentials(cipher, function(err, credentials) {
        if (err) {
            if (callback) callback(err);
            return;
        }
        that.shortUseKey(function(err, key) {
            if (err) {
                callback(err);
                return;
            }
            that.shortUseKey(function(err, secret) {
                if (err) {
                    callback(err);
                    return;
                }
                var ticketData = {
                    requester: request.requester
                    , requested: requested.id
                    , serverNonce: that.nonce()
                    , requesterNonce: request.nonce
                    , id: key.toString('base64')
                    , secret: secret.toString('base64')
                    , oneTimeCredentials: {
                        key: credentials.key.toString('base64')
                        , iv: credentials.iv.toString('base64')
                        , cipher: cipher
                        , hash: that.choose(requester.hashes, requested.hashes)
                    }
                    , hash: that.choose(requester.hashes, requested.hashes)
                    , "ts": new Date().getTime()
                    , expires: request.ts + requested.keysLast
                    , authData: requester.authData
                }

                /**
                 *  Return ticket information.
                 *  @callback Serveros.ServerosMaster~buildTicketCallback
                 *
                 *  @param {Error.ServerosError} error any error that prevents ticket generation.
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
    });
};

/**
 *  Get a ticket, encrypted and signed.
 *
 *  @param {Object} request From the wire, decrypted.
 *  @param {Object} requester The application making the request.
 *  @param {Serveros.ServerosMaster~getTicketCallback} callback A callback for the eventual ticket.
 */
ServerosMaster.prototype.getTicket = function(request, requester, privateKeyNum, callback) {
    if (typeof privateKeyNum != 'number')
        privateKeyNum = 0;
    var that = this
        , privateKey = this.privateKey instanceof Array ? this.privateKey[privateKeyNum] : this.privateKey
        ;
    this.publicKeyFunction(request.requested, null, function(requested) {
        that.buildTicket(request, requested, requester, function(err, ticket) {
            if (err) {
                callback(err);
                return;
            }
            that.encryptAndSign(requested.publicKey
                    , privateKey
                    , JSON.stringify(ticket)
                    , that.chooseCipher(requested.ciphers)
                    , ticket.hash
                    , function(err, message) {
                if (err)
                    callback(err);
                else
                    /**
                     *  Return the ticket.
                     *  @callback Serveros.ServerosMaster~getTicketCallback
                     *
                     *  @param {Error.ServerosError} err any error to prevent ticket generation.
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
};

/**
 *  Prep a response to the server.
 *
 *  @param {Object} ticket A ticket from {@link Serveros.ServerosMaster.getTicket}
 *  @param {Object} requester The application requesting the ticket
 *  @param {Serveros.ServerosMaster~prepReponseCallback} callback a callback for the signed, encrypted response.
 */
ServerosMaster.prototype.prepResponse = function(ticket, requester, publicKeyNum, privateKeyNum, callback) {
    if (typeof publicKeyNum != 'number')
        publicKeyNum = 0;
    if (typeof privateKeyNum != 'number')
        privateKeyNum = 0;
    var that = this
        , response = {
            requester: ticket.raw.requester
            , requested: ticket.raw.requested
            , serverNonce: ticket.raw.serverNonce
            , requesterNonce: ticket.raw.requesterNonce
            , id: ticket.raw.id
            , secret: ticket.raw.secret
            , ts: ticket.raw.ts
            , oneTimeCredentials: ticket.raw.oneTimeCredentials
            , hash: this.chooseHash(requester.hashes)
            , expires: ticket.raw.expires
            , ticket: ticket.ready
        }
        , publicKey = requester.publicKey instanceof Array ? requester.publicKey[publicKeyNum] : requester.publicKey
        , privateKey = this.privateKey instanceof Array ? this.privateKey[privateKeyNum] : this.privateKey
        ;
    this.encryptAndSign(publicKey
            , privateKey
            , JSON.stringify(response)
            , this.chooseCipher(requester.ciphers)
            , response.hash
            , function(err, encrypted) {
        if (err)
            callback(err);
        else

            /**
             *  Returns the desired response, encrypted and signed.
             *  @callback Serveros.ServerosMaster~prepResponseCallback
             *
             *  @param {Error.ServerosError} err Any error
             *  @param {Object} response The signed and encrypted response.
             */
            callback(null, encrypted);
    });
};

/**
 *  Add an authentication endpoint (GET /authenticate) to an Express Application.
 *
 *  @param {ExpressApplication} application an Express application.
 */
ServerosMaster.prototype.addAuthenticationEndpoint = function(application) {
    var that = this;
    application.get('/authenticate', function(req, res, next) {
        var authRequest = JSON.parse(req.query.authRequest);
        that.authenticate(authRequest, function(err, response) {
            if (err) {
                res.status(err.statusCode).json(err.prepResponseBody());
                console.error(err.prepResponseBody());
                if (err.err)
                    console.error(err.err.stack);
            } else
                res.json(response);
        });
    });
};

/**
 *  Choose the best entry between two sets.
 *
 *  Attempts to choose the highest ranked (lowest indexed) entry in each set.
 *
 *  @param {Array} setA The first (larger) set.
 *  @param {Array} setB The second (smaller) set.
 *
 *  @return {mixed} The best choice between the two sets.
 */
ServerosMaster.prototype.choose = function(setA, setB) {
    if (!(setA.length) && !(setB.length))
        return null;
    if (!(setA.length))
        return setB[0];
    if (!(setB.length))
        return setA[0];
    if (setA[0] == setB[0])
        return setA[0];
    if (setA.length < setB.length)
        return this.choose(setB, setA); //Ensure that setB is strictly smaller than setA
    var chosen = null
        , score = setB.length + setA.length + 1;
    for (var i = 0; i < setB.length; i++) {
        var index = setA.indexOf(setB[i])
            , currScore = index + i;
        if (index > -1 && currScore < score) {
            score = currScore;
            chosen = setB[i];
        }
    }
    return chosen;
}

/**
 *  Choose the best hash.
 *
 *  @param {string[]} supported A list of desired Hashes.
 */
ServerosMaster.prototype.chooseHash = function(supported) {
    return this.choose(this.hashPrefs, supported);
};

/**
 *  Choose the best ciphers.
 *
 *  @param {string[]} supported A list of desired Ciphers.
 */
ServerosMaster.prototype.chooseCipher = function(supported) {
    return this.choose(this.cipherPrefs, supported);
};

/**
 *  A simple wrapper around {@link Serveros.Encrypter~decrypt Lib.decrypt}
 *
 *  @param {Buffer|String} data The output of a previous call to Encrypt
 *  @param {Serveros.Encrypter~decryptCallback} callback A callback for the eventual error or plaintext
 */
ServerosMaster.prototype.idecrypt = function(message, callback) {
    this.decrypt(this.privateKey, message, callback);
};

/**
 *  A simple wrapper around {@link Serveros.Encrypter~encrypt Lib.decrypt}
 *
 *  @param {Buffer|String} publicKey A PEM Encoded RSA Key (Public Key)
 *  @param {Object} message A Json Object to be encrypted.
 *  @param {String} cipher The cipher algorithm to use while enciphering.
 *  @param {Serveros.Encrypter~encryptCallback} callback A callback for the eventual error or ciphertext.
 */
ServerosMaster.prototype.iencrypt = function(publicKey, message, cipher, callback) {
    this.encrypt(publicKey, JSON.stringify(message), cipher, callback);
};

/**
 *  A simple wrapper around {@link Serveros.Encrypter~sign Lib.decrypt}
 *
 *  @param {Buffer|String} data The data to be signed.
 *  @param {String} hash The Hash algorithm to use whilst calculating the HMAC
 *  @param {Serveros.Encrypter~signCallback} callback A callback for the eventual error or signature
 */
ServerosMaster.prototype.isign = function(data, hash, callback) {
    this.sign(this.privateKey, data, hash, callback);
};

/**
 *  A simple wrapper around {@link Serveros.Encrypter~verify Lib.decrypt}
 *
 *  @param {Buffer|String} rsaKey A PEM Encoded RSA Key (Public Key)
 *  @param {Buffer|String} data The previously signed data.
 *  @param {String} algorithm The Hash algorithm to use whilst calculating the HMAC
 *  @param {Buffer|String} signature The previously generated Signature - as a buffer or base64
 *      encoded String.
 *  @param {Serveros.Encrypter~verifyCallback} callback A callback for the eventual error or verification Status
 */
ServerosMaster.prototype.iverify = function(rsaKey, data, algorithm, signature, callback) {
    this.verify(rsaKey, data,  algorithm, signature, callback);
};

/**
 *  A small wrapper around {@link Serveros.Encrypter~encryptAndSign Lib.encryptAndSign} which provides the correct
 *  local arguments.
 *
 *  @param {Buffer|String} publicKey A PEM Encoded RSA Key (Public Key)
 *  @param {Object} message A JSON message to be encrypted.
 *  @param {String} cipher The cipher algorithm to use while enciphering.
 *  @param {String} hash The Hash algorithm to use whilst calculating the HMAC
 *  @param {Serveros.Encrypter~encryptAndSignCallback} callback A callback for the eventual error or encrypted/signed message.
 */
ServerosMaster.prototype.iencryptAndSign = function(rsaKey, message, cipher, hash, callback) {
    try {
        this.encryptAndSign(rsaKey
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
};

module.exports = exports = ServerosMaster;
