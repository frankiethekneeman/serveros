var UnsupportedError = require('../UnsupportedError')
    ;

/**
 *  A Hash has been encountered that cannot be supported.
 *  
 *  @class Error.CryptoError.UnsupportedHashError
 *  @extendsUnsupportedError
 *  @inheritdoc
 *  @param {String} hashRequested The requested Hash
 *  @param {String[]} supportedHashes The Hashes actually supported.
 */
function UnsupportedHashError(hashRequested, supportedHashes) {
    UnsupportedError.call(this, hashRequested, supportedHashes, "An unsupported hash was encountered", 490);
};

UnsupportedHashError.prototype = Object.create(UnsupportedError.prototype);

Object.defineProperty(UnsupportedHashError.prototype, 'constructor', {
    enumerable: false
    , value: UnsupportedHashError
});

module.exports = exports = UnsupportedHashError;

