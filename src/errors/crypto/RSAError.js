var WrappedError = require('../WrappedError')
    ;

function RSAError(err) {
    WrappedError.call(this, err, "An Error was encountered while performing RSA Encryption");
}

RSAError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(RSAError.prototype, 'constructor', {
    enumerable: false
    , value: RSAError
});

module.exports = exports = RSAError;
