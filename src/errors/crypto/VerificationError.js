var ServerosError = require('../ServerosError')
    ;

/**
 *  Error for an unverified Message.
 *  
 *  @class Error.CryptoError.VerificationError
 *  @extends ServerosError
 *  @inheritdoc
 */
function VerificationError() {
    ServerosError.call(this, "Verifier Returned False.");
}

VerificationError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(VerificationError.prototype, 'constructor', {
    enumerable: false
    , value: VerificationError
});

module.exports = exports = VerificationError;
