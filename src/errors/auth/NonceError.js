var ServerosError = require('../ServerosError')
    ;

/**
 *  Unmatched Nonces Preventing Authentication.
 *
 *  @class Error.AuthError.NonceError
 *  @extends ServerosError
 *  @inheritdoc
 */
function NonceError() {
    ServerosError.call(this, "Nonces don't match", 403);
}

NonceError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(NonceError.prototype, 'constructor', {
    enumerable: false
    , value: NonceError
});

module.exports = exports = NonceError;
