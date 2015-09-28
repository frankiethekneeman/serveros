var ServerosError = require('../ServerosError')
    ;

function ApplicationResolutionError(applicationType) {
    ServerosError.call(this, "Application resolution failed.", 422);
    if(applicationType) this.applicationType = applicationType;
}

ApplicationResolutionError.prototype = Object.create(ServerosError.prototype);

Object.defineProperty(ApplicationResolutionError.prototype, 'constructor', {
    enumerable: false
    , value: ApplicationResolutionError
});

ApplicationResolutionError.prototype.applicationType = "No Application Type Provided.";
ApplicationResolutionError.prototype.additionalInformation = function() {
    return {
        type: this.applicationType
    };
};

module.exports = exports = ApplicationResolutionError;
