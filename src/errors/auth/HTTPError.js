var WrappedError = require('../WrappedError')
    ;

/**
 *  Signals an Error occured while making an HTTP request.
 *  
 *  @class Error.AuthError.HTTPError
 *  @extends WrappedError
 *  @inheritdoc
 *  @param {Error} err The HTTP error.
 */
function HTTPError(err) {
    WrappedError.call(this, err, "HTTP Error");
}

HTTPError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(HTTPError.prototype, 'constructor', {
    enumerable: false
    , value: HTTPError
});

module.exports = exports = HTTPError;
