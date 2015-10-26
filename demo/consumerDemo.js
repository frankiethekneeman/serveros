var ServerosConsumer = require('../src/classes/ServerosConsumer')
    , fs = require('fs')
    , request = require('request')
    , Hawk = require('hawk')
    , masterPublicKey = fs.readFileSync('./demo/keys/master.pem') + ''
    , myPrivateKey = fs.readFileSync('./demo/keys/serverA')
    , masterServerLocation
    , consumer = new ServerosConsumer({
            id: 'Application A'
            , privateKey: myPrivateKey
            , master: {
                publicKey: masterPublicKey
            }
            , hashes: ['md5', 'sha256', 'sha512', 'sha1']
            , ciphers: ['idea', 'aes256', 'aes192', 'aes128']
        });
    ;

consumer.getCredentials('Application B', 'http://localhost:3501/authenticate', function(err, credentials) {
    if (err) {
        console.log('Error Getting Credentials:');
        console.log(err.prepResponseBody && JSON.stringify(err.prepResponseBody()) || err);
        return;
    } else {
        console.log('The Consumer now has Credentials:');
        console.log(credentials);
    }
    /**
     *  Making a request, using HAWK to authenticate
     */
    var requestOptions = {
            uri:'http://localhost:3501/test'
            , method: 'GET'
            , headers: {}
            , json: true
        }
        , header = Hawk.client.header(requestOptions.uri, requestOptions.method, {credentials: credentials});
    ;
    requestOptions.headers.Authorization = header.field;
    request(requestOptions, function(err, resp, body) {
        if (err) {
            console.log(err);
        }
        else {
            console.log("Hawk Request complete");
            console.log(resp.statusCode);
            console.log(body);
        }
    });
});
