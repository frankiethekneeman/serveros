var UnsupportedError = require('../UnsupportedError')
    ;

/**
 *  A Hash has been encountered that cannot be supported.
 *  
 *  @class Error.CryptoError.UnrecognizedHashError
 *  @extendsUnsupportedError
 *  @inheritdoc
 *  @param {String} hashRequested The requested Hash
 *  @param {String[]} supportedHashes The Hashes actually supported.
 */
function UnrecognizedHashError(hashRequested, supportedHashes) {
    UnsupportedError.call(this, hashRequested, supportedHashes, "An unsupported hash was encountered");
};

UnrecognizedHashError.prototype = Object.create(UnsupportedError.prototype);

Object.defineProperty(UnrecognizedHashError.prototype, 'constructor', {
    enumerable: false
    , value: UnrecognizedHashError
});

module.exports = exports = UnrecognizedHashError;
