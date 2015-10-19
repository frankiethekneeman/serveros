var ServerosError = require('../ServerosError')
    ;

/**
 *  An erroneous response from a server.
 *
 *  @class Error.AuthError.ProtocolError
 *  @extends ServerosError
 *  @inheritdoc
 *  @param {Integer} returnedCode The code the server returned.
 *  @param {mixed} body The body of the response.
 */
function ProtocolError(returnedCode, body) {
    ServerosError.call(this, "Remote Returned Erroneous Response", 500);
    this.returnedCode = returnedCode;
    this.body = body;
}

ProtocolError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(ProtocolError.prototype, 'constructor', {
    enumerable: false
    , value: ProtocolError
});

/**
 *  Return the information about the erroneous response.
 *
 *  @return {Object}
 *  @override
 */
ProtocolError.prototype.additionalInformation = function() {
    return {
        returnedCode: this.returnedCode
        , body: this.body
    };
};


module.exports = exports = ProtocolError;
