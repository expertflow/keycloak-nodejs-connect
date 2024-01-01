const axios = require( 'axios' )
const qs = require( 'querystring' );

/* axios.interceptors.request.use( x => {
    // to avoid overwriting if another interceptor
    // already defined the same object (meta)
    x.meta = x.meta || {}
    x.meta.requestStartedAt = new Date().getTime();
    return x;
} )

axios.interceptors.response.use( x => {
    console.log( `Execution time for: ${x.config.url} - ${x.config.method} - ${new Date().getTime() - x.config.meta.requestStartedAt} ms` )
    return x;
},
    // Handle 4xx & 5xx responses
    x => {
        console.error( `Execution time for: ${x.config.url} - ${x.config.method} - ${new Date().getTime() - x.config.meta.requestStartedAt} ms` )
        throw x;
    }
) */


module.exports = {
    httpRequest: ( config, flag ) => {   //flag identifies which configuration to be sent as stringified 
        var localConfig = { ...config };
        if ( flag ) {
            localConfig.data = qs.stringify( localConfig.data );
        }
        return axios( localConfig );
    }
}
