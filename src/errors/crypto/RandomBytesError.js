var WrappedError = require('../WrappedError')
    ;

function RandomBytesError(err) {
    WrappedError.call(this, err, "An Error was encountered while Gathering Entropy");
}

RandomBytesError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(RandomBytesError.prototype, 'constructor', {
    enumerable: false
    , value: RandomBytesError
});

module.exports = exports = RandomBytesError;
