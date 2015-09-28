var WrappedError = require('../WrappedError')
    ;

function JSONError(err) {
    WrappedError.call(this, err, "JSON Error");
}

JSONError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(JSONError.prototype, 'constructor', {
    enumerable: false
    , value: JSONError
});

module.exports = exports = JSONError;
