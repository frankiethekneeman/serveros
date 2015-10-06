var ServerosError = require('../ServerosError')
    ;

function UnrecognizedHashError(hashRequested, supportedHashes) {
    ServerosError.call(this, "An unsupported hash was encountered");
    this.requested = hashRequested;
    this.supported = supportedHashes;
}

UnrecognizedHashError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(UnrecognizedHashError.prototype, 'constructor', {
    enumerable: false
    , value: UnrecognizedHashError
});

UnrecognizedHashError.prototype.additionalInformation = function() {
    return {
        requested: this.requested
        , supported: this.supported
    }
};

module.exports = exports = UnrecognizedHashError;
