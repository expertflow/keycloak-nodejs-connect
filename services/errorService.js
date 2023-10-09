

class ErrorService {

    constructor () {

    }

    async handleError( err ) {

        console.log( err );

        if ( err.code ) {

            switch ( err.code ) {

                case 'ETIMEDOUT':
                    return {
                        status: 408,
                        reason: `Keycloak server unaccessable against Keycloak URL, This might be due to Network Issue or Server Unavailability`
                    };
                case 'ENOTFOUND':
                    return {
                        status: 404,
                        reason: `Hostname Not Found, Keycloak server unaccessable against Keycloak URL. Unable to resolve Hostname, This maybe due to wrong Host URL or DNS server issue`,
                    };
                default:
                    return {
                        status: err.response.status,
                        reason: err.response.data,
                    };
            }

        } else {

            if ( err.response ) {

                if ( err.response.data ) {

                    let errorData = err.response.data;

                    if ( errorData.error ) {

                        let error = errorData.error;

                        switch ( error ) {

                            case 'invalid_client':

                                return {
                                    status: err.response.status,
                                    reason: 'CLIENT_ID value is not valid in Keycloak Config, please provide a valid CLIENT_ID',
                                };
                            case 'unauthorized_client':

                                return {
                                    status: err.response.status,
                                    reason: 'CLIENT_SECRET (credentials.secret in Keycloak Config) value is not valid in Keycloak Config, please provide a valid CLIENT_SECRET',
                                };
                            case 'Realm does not exist':

                                return {
                                    status: err.response.status,
                                    reason: 'Realm is not valid in Keycloak Config, please provide a valid Keycloak Realm',
                                };
                            case 'invalid_grant':

                                return {
                                    status: err.response.status,
                                    reason: 'Provided User Credentials are not valid, please provide a valid User Credentials',
                                };
                            default:
                                return {
                                    status: err.response.status,
                                    reason: err.response.data,
                                };

                        }

                    } else {

                        return {
                            status: err.response.status,
                            reason: err.response.data,
                        };

                    }

                }


            }

            return {
                status: 'ReferenceError',
                reason: "Some variable or function either hasn't been declared or is out of scope"
            };
        }
    }
}

module.exports = ErrorService;