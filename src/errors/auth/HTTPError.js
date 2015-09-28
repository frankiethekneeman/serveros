var WrappedError = require('../WrappedError')
    ;

function HTTPError(err) {
    WrappedError.call(this, err, "HTTP Error");
}

HTTPError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(HTTPError.prototype, 'constructor', {
    enumerable: false
    , value: HTTPError
});

module.exports = exports = HTTPError;
