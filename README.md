Authentication and Authorization for the modern age.

Security is hard.  And when it's not implemented
by dedicated experts it tends to get underdone.  People reuse the same keys over and over again.  They
choose keys that are easy to write or remember.  The don't bother to cycle those keys.  Plus, it's hard
to update keys if one of your many applications is compromised.  Serveros is here to try and make that
better.  Based loosely on my understanding of the Kerberos protocol, it allows you to authentiate
your applications to each other via a third party under your control.  It uses RSA encryption, and 
can be used safely across non-encrypted HTTP.

## Okay, how?

    var Serveros = require('serveros');

What do you want to do next?

### I want to run an Authentication Server.

Of course you do:

    var express = require('express')
        , master = new Serveros.ServerosMaster({
            privateKey: //Your master needs its own Private Key.
            , publicKeyFunction: function(id, service, callback) {
                //you need to provide a function that turns IDS into public Key data.
                //When you're done...
                callback({
                    id: //This can look like whatever you want.
                    , publicKey: //The good stuff
                    , hashes:    //What hashes does this application support?
                    , ciphers:   //What ciphers does this application support?
                    , keysLast:  //How many milliseconds should these keys last?
                    , authData:  //Whatever additional information you want to pass
                });
            }
            , hashes:   //Pick your favorite Hashes (if you want)
            , ciphers:  //And your favorite ciphers (if you want)
        })
        , application = express()
        ;
    /**
     *  add GET /authenticate to your application.
     */
    master.addAuthenticationEndpoint(application);

    /**
     *  Launch it.
     */
    var server = application.listen(3500, 'localhost', function () {
        var host = server.address().address;
        var port = server.address().port;
      
        console.log('Example app listening at http://%s:%s', host, port);
    });

No joke.  You did it.

### That's easy.  What if I want to provide a service via this Authentication system?
    var express = require('express')
        , provider = new Serveros.ServerosServiceProvider({
            id: //Whatever you want it to be.
            , privateKey: //Each serviceProvider needs a keypair.
            , master: {
                publicKey: //This is your ticket to success.
            }
            , hashes:   //Pick your favorite Hashes (if you want)
            , ciphers:  //And your favorite ciphers (if you want)
        })
        /**
         *  Some day, you're going to want to find a better way to store keys than in
         *  memory.  Check out the documentation.
         */
        , authenticator = new Serveros.HawkAuthenticator()
        , application = express()
        ;
    
    //Add an authenticate endpoint
    application.post('/authenticate', provider.expressValidator(authenticator.credentialsAccepter()));
    //Add a nice little filter to do your authing.
    application.use(authenticator.expressAuthorizer());

    /**
     *  Launch it.
     */
    var server = application.listen(3501, 'localhost', function () {
        var host = server.address().address;
        var port = server.address().port;
      
        console.log('Example app listening at http://%s:%s', host, port);
    });

There you go.  Now when someone's authed to your API, their requests will have a little extra informaion:

    application.get('/amIAuthed', function(req, res, next) {
        res.json({
            'Authed As': req.authedAs   //This is the ID for the application as provided to the master.
            , 'Auth Data': req.authData //This is the extra AuthData provided to the master.
        });
    });

It's that simple.

### So, it must be hard to consume these apis, right?

Have you been paying attention?

    var ServerosConsumer = require('../src/classes/ServerosConsumer')
        , request = require('request')
        , Hawk = require('hawk')
        , consumer = new Serveros.ServerosConsumer({
            id: //Whatever you like, again.
            , privateKey: //Everyone gets a keypair
            , master: {
                location: //Tell us where the Master server is hiding, or we'll guess localhost:3500
                , publicKey: //Get this offline somewhere.
            }
            , hashes:   //Pick your favorite Hashes (if you want)
            , ciphers:  //And your favorite ciphers (if you want)
        })
        ;

    consumer.getCredentials('Application B', 'http://localhost:3501/authenticate', function(err, credentials) {
        if (err) {
            //Wait, something went wrong.
        } else {
            /**
             *  You now have some credentials for aplication B.  Give them a shot.
             *  Making a request, using HAWK to authenticate
             */
            var requestOptions = {
                    uri:'http://localhost:3501/amIAuthed'
                    , method: 'GET'
                    , headers: {}
                    , json: true
                }
                , header = Hawk.client.header(requestOptions.uri, requestOptions.method, {credentials: credentials});
            ;
            requestOptions.headers.Authorization = header.field;
            request(requestOptions, function(err, resp, body) {
                console.log(body);
            });
        }
    });


It's easy.  Get some.

### Does it work?

    /bin/bash scripts/demo.sh

## Documentation

    /bin/bash scripts/doc.sh
 
It's in `jsdoc/output`.  Soon we'll have a website or something.

## Contributing 

Please do.  Keep your commits sensible.  Fix security holes.  I'm definitely an amateur.

## Disclaimer

I do not claim this to be a perfect security system.  It's offered up for free in good faith
to try and make our applications more secure, but I am an amateur.
