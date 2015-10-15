# Messaging In Serveros

## Consumer to Master, "Auth Request"

     {
        requester:              //My ID
        , requested:            //Provider ID
        , nonce:                //Random Bullshit
        , ts:                   //What time is it?  Millis
        , hash:                 //Hash used to sign the request
        , supportedHashes:      //Hashes I can use
        , supportedCiphers:     //Ciphers I can use
    }

## Master to Provider, via Consumer, "Auth Ticket"

    {
        requester:               //Consumer ID
        , requested:             //Provider ID
        , serverNonce:           //New Nonce
        , requesterNonce:        //Nonce from Auth Request
        , id:                    //64Bytes of entropy
        , secret:                //64 more bytes of entryop
        , oneTimeCredentials: {
            key:                 //A key of the appropriate size
            , iv:                //An initial Vector of the appropriate Size   
            , cipher:            //A Cipher supported by Consumer And Provider
            , hash:              //A Hash algo supported by Consumer and Provider
        }
        , hash:                  //Hash used to sign this request.
        , ts:                    //timestamp 
        , expires:               //When these credentials expire
        , authData:              //Arbitrary
    }

## Master to Consumer, "Auth Response"


    {
        requester:               //Consumer ID
        , requested:             //Provider ID
        , serverNonce:           //Nonce from Auth Ticket
        , requesterNonce:        //Nonce from Auth Request
        , id:                    //ID from Auth Ticket
        , secret:                //Secret from Auth Ticket
        , oneTimeCredentials: {  //Same Credentials as Auth Ticket
            key:
            , iv:
            , cipher:
            , hash:
        }
        , hash:                  //Hash used to sign this request.
        , ts:                    //timestamp 
        , expires:               //When these credentials expire
        , ticket:                //The encrypted, signed Auth Ticket
    };

## Consumer to Provider, "Ticket Presentation"
    {
        "id": ID Object, Enciphered with Key and IV from server.
        , "ticket":  The Encrypted, Signed Auth Ticket
    }

### ID Object

    {
        id:                 //My ID
        , serverNonce:      //Nonce from Auth Response
        , requesterNonce:   //Nonce from Auth Request
        , finalNonce:       //New Nonce
        , iv:               //New IV 
        , ts:               //New Time Stamp
    }

## Provider to Consumer, "Acknowledgement"

    {
        serverNonce:        //Nonce from Auth Ticket
        , requesterNonce:   //Nonce from Auth Request
        , finalNonce:       //Nonce from ID Object
        , ts:               //New Timestamp
    }
   
