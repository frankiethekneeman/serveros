/**
 *  Errors.
 *  @namespace Error
 */
/**
 *  The base error for all Errors.
 *  
 *  @class Error.ServerosError
 *  @param {String} [message] a simple message describing the Error.
 *  @param {Integer} [statusCode] A status code for use.
 */
function ServerosError(message, statusCode) {
    if (message) this.message = message;
    if (statusCode) this.statusCode = statusCode;
}

// In theory this extends Error... but... not well.
ServerosError.prototype = Object.create(Error.prototype);

Object.defineProperty(ServerosError.prototype, 'constructor', {
    enumerable: false
    , value: ServerosError
});

/**
 *  The HTTP Status code to be used if this Error crops up in an HTTP endpoint.
 *  
 *  @default
 */
ServerosError.prototype.statusCode = 500;

/**
 *  A message that might explain what's going on.
 *  
 *  @default
 */
ServerosError.prototype.message = "Malformed Error."

/**
 *  A function that returns an object to be added to JSON HTTP responses with information
 *  about the Error in question.
 *  
 *  @return {Object}
 */
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

/**
 *  This should be overridden by subclasses to provide more information.
 *  
 *  @return {Object}
 */
ServerosError.prototype.additionalInformation = function() {
    return null;
};

module.exports = exports = ServerosError;
