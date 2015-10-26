var WrappedError = require('../WrappedError')
    ;

/**
 *  The PublicKeyFunction threw an error.
 *
 *  @class Error.MasterError.PublicKeyFunctionError
 *  @extends WrappedError
 *  @inheritdoc
 *
 *  @param {Error} err The error thrown.
 */
function PublicKeyFunctionError(err) {
    WrappedError.call(this, err, "An Error was encountered while performing PublicKeyFunction");
}

PublicKeyFunctionError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(PublicKeyFunctionError.prototype, 'constructor', {
    enumerable: false
    , value: PublicKeyFunctionError
});

module.exports = exports = PublicKeyFunctionError;
