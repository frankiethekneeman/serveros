var WrappedError = require('../WrappedError')
    ;

function CipherError(err) {
    WrappedError.call(this, err, "An Error was encountered while enciphering or deciphering data.");
}

CipherError.prototype = Object.create(WrappedError.prototype);

Object.defineProperty(CipherError.prototype, 'constructor', {
    enumerable: false
    , value: CipherError
});

module.exports = exports = CipherError;
