var ServerosError = require('../ServerosError')
    ;

/**
 *  Error taking an ID and turning it into Application information.
 *
 *  @class Error.MasterError.ApplicationResolutionError
 *  @extends ServerosError
 *  @inheritdoc
 *  @param {String} applicationType the type of application being resolved - requester or requested.
 *  @param {mixed} [cause] The underlying error bubbled up by the publicKeyFunction
 */
function ApplicationResolutionError(applicationType, cause) {
    ServerosError.call(this, "Application resolution failed.", 422);
    if(applicationType) this.applicationType = applicationType;
    if(cause) this.cause = cause;
}

ApplicationResolutionError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(ApplicationResolutionError.prototype, 'constructor', {
    enumerable: false
    , value: ApplicationResolutionError
});

/**
 *  The Type of application we failed to resolve.
 *
 *  @default
 */
ApplicationResolutionError.prototype.applicationType = "No Application Type Provided.";

/**
 *  The underlying error, bubble up from below.
 *
 *  @default
 */
ApplicationResolutionError.prototype.cause = null;

/**
 *  Return the type of application which failed resoltion.
 *
 *  @return {Object}
 */
ApplicationResolutionError.prototype.additionalInformation = function() {
    return {
        type: this.applicationType
        , cause: this.cause
    };
};

module.exports = exports = ApplicationResolutionError;
