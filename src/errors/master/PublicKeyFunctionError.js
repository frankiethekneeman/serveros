var WrappedError = require('../WrappedError')
    ;

function PublicKeyFunctionError(err) {
    WrappedError.call(this, err, "An Error was encountered while performing PublicKeyFunction");
}

PublicKeyFunctionError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(PublicKeyFunctionError.prototype, 'constructor', {
    enumerable: false
    , value: PublicKeyFunctionError
});

module.exports = exports = PublicKeyFunctionError;
