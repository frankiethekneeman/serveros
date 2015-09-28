var ServerosError = require('../ServerosError')
    ;

function NonceError() {
    ServerosError.call(this, "Nonces don't match");
}

NonceError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(NonceError.prototype, 'constructor', {
    enumerable: false
    , value: NonceError
});

module.exports = exports = NonceError;
