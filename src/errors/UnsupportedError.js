var ServerosError = require('./ServerosError')
    ;

/**
 *  An unsupported entity was encountered.
 *  
 *  @class Error.UnsupportedError
 *  @extends ServerosError
 *  @inheritdoc
 *  @param {String} requested the requested entity
 *  @param {String[]} supported The list of supported entities
 *  @param {String} [message] a simple message describing the Error.
 *  @param {Integer} [statusCode] A status code for use in HTTP responses.
 */
function UnsupportedError(requested, supported, message, statusCode) {
    ServerosError.call(this, message, statusCode);
    if (requested) this.requested = requested;
    if (supported) this.supported = supported;
}

UnsupportedError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(UnsupportedError.prototype, 'constructor', {
    enumerable: false
    , value: UnsupportedError
});

/**
 *  The requested entity.
 *  @default
 */
UnsupportedError.prototype.requested = "No Requested item was passed";

/**
 *  A list of supported entities.
 *  @default
 */
UnsupportedError.prototype.supported = [];

/**
 *  Return the requested/supported entries in a readable format.
 *  
 *  @return {Object}
 *  @override
 */
UnsupportedError.prototype.additionalInformation = function() {
    return {
        requested: this.requested
        , supported: this.supported
    }
};

module.exports = exports = UnsupportedError;

