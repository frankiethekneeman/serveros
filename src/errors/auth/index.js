/**
 *  A Bundle Module for things that might go wrong whilst Authing.
 *
 *  @module AuthError
 */
module.exports = exports = {

    /**
     *  {@link Error.AuthError.NonceError NonceError}
     */
    NonceError    : require('./NonceError')     ,

    /**
     *  {@link Error.AuthError.StaleError StaleError}
     */
    StaleError    : require('./StaleError')     ,

    /**
     *  {@link Error.AuthError.HTTPError HTTPError}
     */
    HTTPError     : require('./HTTPError')      ,

    /**
     *  {@link Error.AuthError.JSONError JSONError}
     */
    JSONError     : require('./JSONError')      ,

    /**
     *  {@link Error.AuthError.ProtocolError ProtocolError}
     */
    ProtocolError : require('./ProtocolError')
}
