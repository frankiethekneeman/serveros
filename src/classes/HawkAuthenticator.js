var Hawk = require('hawk')
    , inMemoryHash = {}
    ;

/**
 *  A helper class to do Hawk Authentication for Consumers.
 *  @class Plugins.HawkAuthenticator
 *
 *  @param {Object} [storageInterface=InMemoryStorage]  A storage interface for the Credentials as they're unpacked.
 *  @param {Plugins.HawkAuthenticator~StorageInterfaceStore} storageInterface.store
 *  @param {Plugins.HawkAuthenticator~StorageInterfaceRetrieve} storageInterface.retrieve
 *  @param {Plugins.HawkAuthenticator~StorageInterfacePurge} storageInterface.purge
 */
function HawkAuthenticator(storageInterface) {
    this.storage = storageInterface || {
        /**
         *  Store some credentials for later retrieval.
         *
         *  @callback Plugins.HawkAuthenticator~StorageInterfaceStore
         *  @param {String} key The key which will be used to retrieve the credentials.
         *  @param {Object} credentials The credentials which will need retrieval.
         *  @param {Plugins.HawkAuthenticator~thinCallback} callback A callback for the results of the operation.
         */
        store: function(key, credentials, callback) {
            inMemoryHash[key]  = credentials;
            process.nextTick( function() {
                if (callback) callback(true);
            });
        },

        /**
         *  Retrieve some credentials.
         *
         *  @callback Plugins.HawkAuthenticator~StorageInterfaceRetrieve
         *  @param {String} key The key which was used to store the credentials.
         *  @param {Plugins.HawkAuthenticator~thinCallback} callback A callback for the results of the operation.
         */
        retrieve: function(id, callback) {
            var toReturn = inMemoryHash[id];
            process.nextTick( function() {
                if (callback) callback(toReturn);
            });
        },

        /**
         *  Eliminate some credentials from
         *
         *  @callback Plugins.HawkAuthenticator~StorageInterfacePurge
         *  @param {String} key The key which was used to store the credentials.
         *  @param {Plugins.HawkAuthenticator~thinCallback} callback A callback for the results of the operation.
         */
        purge: function(id, callback) {
            delete inMemoryHash[id];
            process.nextTick( function() {
                if (callback) callback(true);
            });
        }
    }
}

HawkAuthenticator.prototype = {
    /**
     *  Create a credentials acceptance function to pass into {@link ServerosServiceProvider.expressValidator}
     *
     *  @return {ServerosServiceProvider~validatorCallback} a credentials function.
     */
    credentialsAccepter: function() {
        var that = this;
        return function(credentials) {
            that.storage.store(credentials.id, credentials);
        };
    },
    /**
     *  Create a credentials acceptance function to pass into {@link ServerosServiceProvider.expressValidator}
     *
     *  @return {function} an Express filter.
     */
    expressAuthorizer: function() {
        var that = this;
        return function(req, res, next) {
            Hawk.server.authenticate(req, function(id, callback) {
                that.storage.retrieve(id, function(credentials) {
                    if (!credentials) {
                        callback("No Credentials Found.");
                        return;
                    }
                    if (Date.now() < credentials.expires) {
                        that.storage.purge(id, function() {
                            if (callback) callback("Credentials Expired");
                        });
                    }
                    var hawkCredentials = {
                        key: credentials.secret
                        , algorithm: credentials.hash
                        , authData: credentials.authData
                        , consumer: credentials.requester
                    }
                    callback(null, hawkCredentials);
                });
            }, {}, function(err, credentials, artifacts) {
                if (!err) {
                    req.authedAs = credentials.consumer;
                    req.authData = credentials.authData;
                } else {
                    req.authErr = err
                }
                next();
            });
        };
    }
}

module.exports = exports = HawkAuthenticator;

/**
 *  @callback Plugins.HawkAuthenticator~thinCallback
 *  @param {mixed} the result of the operation.
 */
