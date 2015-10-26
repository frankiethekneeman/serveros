/**
 *  A Module of Errors Specific to the Authentication Master.
 *
 *  @module MasterError
 */
module.exports = exports = {
    /**
     *  {@link Error.MasterError.PublicKeyFunctionError PublicKeyFunctionError}
     */
    PublicKeyFunctionError     : require('./PublicKeyFunctionError')      ,
    /**
     *  {@link Error.MasterError.ApplicationResolutionError ApplicationResolutionError}
     */
    ApplicationResolutionError : require('./ApplicationResolutionError')
}
