var WrappedError = require('../WrappedError')
    ;

/**
 *  An error while JSON encoding/decoding.
 *
 *  @class Error.AuthError.JSONError
 *  @extends WrappedError
 *  @inheritdoc
 *  @param {Error} err The error.
 */
function JSONError(err) {
    WrappedError.call(this, err, "JSON Error", 400);
}

JSONError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(JSONError.prototype, 'constructor', {
    enumerable: false
    , value: JSONError
});

module.exports = exports = JSONError;
