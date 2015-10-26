/**
 *  @module Serveros
 */
module.exports = exports = {

    /**
     *  {@link Serveros.ServerosMaster ServerosMaster}
     */
    ServerosMaster          : require("./src/classes/ServerosMaster")          ,
    /**
     *  {@link Serveros.ServerosServiceProvider ServerosServiceProvider}
     */
    ServerosServiceProvider : require("./src/classes/ServerosServiceProvider") ,
    /**
     *  {@link Serveros.ServerosConsumer ServerosConsumer}
     */
    ServerosConsumer        : require("./src/classes/ServerosConsumer")        ,
    /**
     *  {@link Plugins.HawkAuthenticator HawkAuthenticator}
     */
    HawkAuthenticator       : require("./src/classes/HawkAuthenticator")
}
