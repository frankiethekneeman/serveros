var ServerosError = require('../ServerosError')
    ;

/**
 *  A stale Authentication request.
 *  
 *  @class Error.AuthError.StaleError
 *  @extends ServerosError
 *  @inheritdoc
 */
function StaleError() {
    ServerosError.call(this, "Stale Authentication Request.", 401);
}

StaleError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(StaleError.prototype, 'constructor', {
    enumerable: false
    , value: StaleError
});

/**
 *  Return the Server clock in Milliseconds since the Epoch.
 *  
 *  @returns {Object}
 *  @override
 */
StaleError.prototype.additionalInformation = function() {
    return {
        ServerClock: new Date().getTime()
    };
};

module.exports = exports = StaleError;
