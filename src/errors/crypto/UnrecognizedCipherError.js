var ServerosError = require('../ServerosError')
    ;

function UnrecognizedCipherError(cipherRequested, supportedCiphers) {
    ServerosError.call(this, "An unsupported cipher was encountered");
    this.requested = cipherRequested;
    this.supported = supportedCiphers;
}

UnrecognizedCipherError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(UnrecognizedCipherError.prototype, 'constructor', {
    enumerable: false
    , value: UnrecognizedCipherError
});

UnrecognizedCipherError.prototype.additionalInformation = function() {
    return {
        requested: this.requested
        , supported: this.supported
    }
};

module.exports = exports = UnrecognizedCipherError;
