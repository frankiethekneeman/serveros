function ServerosError(message, statusCode) {
    if (message) this.message = message;
    if (statusCode) this.statusCode = statusCode;
}

ServerosError.prototype = Object.create(Error.prototype);

Object.defineProperty(ServerosError.prototype, 'constructor', {
    enumerable: false
    , value: ServerosError
});

ServerosError.prototype.statusCode = 500;
ServerosError.prototype.message = "Malformed Error."

ServerosError.prototype.prepResponseBody = function() {
    var toReturn = {
        'status': this.statusCode
        , 'message': this.message
    }
    , additionalInformation = this.additionalInformation();
    if (additionalInformation)
        toReturn.additionalInformation = additionalInformation;
    return toReturn;
};

ServerosError.prototype.additionalInformation = function() {
    return null;
};

module.exports = exports = ServerosError;
