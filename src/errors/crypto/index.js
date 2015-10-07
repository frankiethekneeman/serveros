/**
 *  A Bundle Module for things that might go wrong while Enciphering, Deciphering,
 *  encrypting, decrypting, signing or verifying data.
 *  
 *  @module CryptoError
 */
module.exports = exports = {

    /**
     *  {@link Error.CryptoError.RandomBytesError RandomBytesError}
     */
    RandomBytesError        : require('./RandomBytesError')        ,

    /**
     *  {@link Error.CryptoError.CipherError CipherError}
     */
    CipherError             : require('./CipherError')             ,

    /**
     *  {@link Error.CryptoError.UnrecognizedCipherError UnrecognizedCipherError}
     */
    UnrecognizedCipherError : require('./UnrecognizedCipherError') ,

    /**
     *  {@link Error.CryptoError.UnsupportedCipherError UnsupportedCipherError}
     */
    UnsupportedCipherError : require('./UnsupportedCipherError') ,

    /**
     *  {@link Error.CryptoError.UnrecognizedHashError UnrecognizedHashError}
     */
    UnrecognizedHashError   : require('./UnrecognizedHashError')   ,

    /**
     *  {@link Error.CryptoError.UnsupportedHashError UnsupportedHashError}
     */
    UnsupportedHashError   : require('./UnsupportedHashError')   ,

    /**
     *  {@link Error.CryptoError.RSAError RSAError}
     */
    RSAError                : require('./RSAError')                ,

    /**
     *  {@link Error.CryptoError.VerificationError VerificationError}
     */
    VerificationError       : require('./VerificationError')
};
