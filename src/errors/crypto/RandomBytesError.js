var WrappedError = require('../WrappedError')
    ;

/**
 *  An error generating Random Bytes.
 *
 *  @class Error.CryptoError.RandomBytesError
 *  @extends WrappedError
 *  @inheritdoc
 *  @param {Error} err The error encountered.
 */
function RandomBytesError(err) {
    WrappedError.call(this, err, "An Error was encountered while Gathering Entropy");
};

RandomBytesError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(RandomBytesError.prototype, 'constructor', {
    enumerable: false
    , value: RandomBytesError
});

module.exports = exports = RandomBytesError;
