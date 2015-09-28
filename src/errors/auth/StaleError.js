var ServerosError = require('../ServerosError')
    ;

function StaleError() {
    ServerosError.call(this, "Stale Authentication Request.", 401);
}

StaleError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(StaleError.prototype, 'constructor', {
    enumerable: false
    , value: StaleError
});

StaleError.prototype.additionalInformation = function() {
    return {
        ServerClock: new Date().getTime()
    };
};

module.exports = exports = StaleError;
