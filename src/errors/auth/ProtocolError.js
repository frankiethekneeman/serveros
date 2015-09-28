var ServerosError = require('../ServerosError')
    ;

function ProtocolError(returnedCode, body) {
    ServerosError.call(this, "Remote Returned Erroneous Response");
    this.returnedCode = returnedCode;
    this.body = body;
}

ProtocolError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(ProtocolError.prototype, 'constructor', {
    enumerable: false
    , value: ProtocolError
});

ProtocolError.prototype.additionalInformation = function() {
    return {
        returnedCode: this.returnedCode
        , body: this.body
    };
};


module.exports = exports = ProtocolError;
