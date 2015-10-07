var WrappedError = require('../WrappedError')
    ;

/**
 *  For Errors Ciphering or Deciphering Data.
 *  
 *  @class Error.CryptoError.CipherError
 *  @extends WrappedError
 *  @inheritdoc
 *  
 *  @param {Error} err The error encountered.
 */
function CipherError(err) {
    WrappedError.call(this, err, "An Error was encountered while enciphering or deciphering data.");
}

CipherError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(CipherError.prototype, 'constructor', {
    enumerable: false
    , value: CipherError
});

module.exports = exports = CipherError;
