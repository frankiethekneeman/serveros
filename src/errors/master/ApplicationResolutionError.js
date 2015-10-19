var ServerosError = require('../ServerosError')
    ;

/**
 *  Error taking an ID and turning it into Application information.
 *
 *  @class Error.MasterError.ApplicationResolutionError
 *  @extends ServerosError
 *  @inheritdoc
 *  @param {String} applicationType the type of application being resolved - requester or requested.
 */
function ApplicationResolutionError(applicationType) {
    ServerosError.call(this, "Application resolution failed.", 422);
    if(applicationType) this.applicationType = applicationType;
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
 *  Return the type of application which failed resoltion.
 *
 *  @return {Object}
 */
ApplicationResolutionError.prototype.additionalInformation = function() {
    return {
        type: this.applicationType
    };
};

module.exports = exports = ApplicationResolutionError;
