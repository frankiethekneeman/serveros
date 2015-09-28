var fs = require('fs') 
    , publicKeys = {
        "Application A": fs.readFileSync('./demo/keys/serverA.pem') + ''
        , "Application B": fs.readFileSync('./demo/keys/serverB.pem') + ''
    }
    , myPrivateKey = fs.readFileSync('./demo/keys/master') 
    , keyFunction = function(id, requester, callback) {
        process.nextTick(function() {
            callback({
                'id': id
                , publicKey: publicKeys[id]
                , hashes: ['sha256', 'sha512']
                , ciphers: ['aes256', 'aes192']
                , keysLast: 3600000
                , authData: ["Perm1", "Perm2"]
            });
        });
    }
    , ServerosMaster = require('../src/classes/ServerosMaster.js')
    ;

var express = require('express')
    , master = new ServerosMaster({
        privateKey: myPrivateKey
        , publicKeyFunction: keyFunction
        , hashes: ['sha256', 'sha512']
        , ciphers: ['aes256', 'aes192']
    })
    , application = express()
master.addAuthenticationEndpoint(application);

var server = application.listen(3500, 'localhost', function () {
    var host = server.address().address;
    var port = server.address().port;
  
    console.log('Example app listening at http://%s:%s', host, port);
});
