var WrappedError = require('../WrappedError')
    ;

/**
 *  An Error during RSA Encryption/Decryption.
 *  
 *  @class Error.CryptoError.RSAError
 *  @extends WrappedError
 *  @inheritdoc
 *  @param {Error} err The encountered error.
 */
function RSAError(err) {
    WrappedError.call(this, err, "An Error was encountered while performing RSA Encryption");
};

RSAError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(RSAError.prototype, 'constructor', {
    enumerable: false
    , value: RSAError
});

module.exports = exports = RSAError;
