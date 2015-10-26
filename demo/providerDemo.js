var ServerosServiceProvider = require('../src/classes/ServerosServiceProvider')
    , HawkAuthenticator = require('../src/classes/HawkAuthenticator')
    , Hawk = require('hawk')
    , express = require('express')
    , fs = require('fs')
    , bodyParser = require('body-parser')
    , masterPublicKey = fs.readFileSync('./demo/keys/master.pem') + ''
    , myPrivateKey = fs.readFileSync('./demo/keys/serverB')
    , application = express()
    , provider = new ServerosServiceProvider({
            id: 'Application B'
            , privateKey: myPrivateKey
            , master: {
                publicKey: masterPublicKey
            }
            , hashes: ['sha256', 'sha1', 'sha512']
            , ciphers: ['aes256', 'aes192', 'aes128']
        })
    , hawkstuff = null
    , authenticator = new HawkAuthenticator();
    ;

application.use('/authenticate', bodyParser.json());
application.post('/authenticate', provider.expressValidator(authenticator.credentialsAccepter()));
application.use(authenticator.expressAuthorizer());
application.get('/test', function(req, res, next) {
    res.json({'Authed As': req.authedAs, 'Auth Data': req.authData});
});
var server = application.listen(3501, 'localhost', function () {
    var host = server.address().address;
    var port = server.address().port;

    console.log('Example app listening at http://%s:%s', host, port);
});
