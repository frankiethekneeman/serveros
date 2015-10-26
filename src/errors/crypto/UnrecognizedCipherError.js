var UnsupportedError = require('../UnsupportedError')
    ;

/**
 *  A cipher that cannot be supported was encountered.
 *
 *  @class Error.CryptoError.UnrecognizedCipherError
 *  @extends UnsupportedError
 *  @inheritdoc
 *  @param {String} cipherRequested The name of the requested Cipher.
 *  @param {String[]} supportedCiphers The list of supported Ciphers.
 */
function UnrecognizedCipherError(cipherRequested, supportedCiphers) {
    UnsupportedError.call(this, cipherRequested, supportedCiphers, "An unrecognized cipher was encountered");
};

UnrecognizedCipherError.prototype = Object.create(UnsupportedError.prototype);

Object.defineProperty(UnrecognizedCipherError.prototype, 'constructor', {
    enumerable: false
    , value: UnrecognizedCipherError
});

module.exports = exports = UnrecognizedCipherError;
