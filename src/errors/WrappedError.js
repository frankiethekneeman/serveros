var ServerosError = require('./ServerosError')
    ;

function WrappedError(err, message) {
    ServerosError.call(this, message);
    if (err) this.err = err;
}

WrappedError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(WrappedError.prototype, 'constructor', {
    enumerable: false
    , value: WrappedError
});

WrappedError.prototype.err = {
    message: "No Error Provided."
}
WrappedError.prototype.additionalInformation = function() {
    return {
        rootError: this.err.message
    }
};

module.exports = exports = WrappedError;
