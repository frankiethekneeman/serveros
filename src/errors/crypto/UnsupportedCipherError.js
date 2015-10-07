var UnsupportedError = require('../UnsupportedError')
    ;

/**
 *  A cipher that cannot be supported was encountered.
 *  
 *  @class Error.CryptoError.UnsupportedCipherError
 *  @extends UnsupportedError
 *  @inheritdoc
 *  @param {String} cipherRequested The name of the requested Cipher.
 *  @param {String[]} supportedCiphers The list of supported Ciphers.
 */
function UnsupportedCipherError(cipherRequested, supportedCiphers) {
    UnsupportedError.call(this, cipherRequested, supportedCiphers, "An unsupported cipher was encountered", 409);
};

UnsupportedCipherError.prototype = Object.create(UnsupportedError.prototype);

Object.defineProperty(UnsupportedCipherError.prototype, 'constructor', {
    enumerable: false
    , value: UnsupportedCipherError
});

module.exports = exports = UnsupportedCipherError;

