

class ErrorService {

    constructor () {

    }

    async handleError( err ) {

        if ( err.error_message && err.error_detail ) {
            return err.error_detail;
        }

        if ( err.code && err.code != 'ERR_BAD_REQUEST' ) {

            switch ( err.code ) {

                case 'ETIMEDOUT':
                    return {
                        status: 408,
                        reason: `Keycloak Server Inaccessible: The keycloak server is inaccessible at the specified URL. This might be due to a network issue or server unavailability.`
                    };
                case 'ENOTFOUND':
                    return {
                        status: 404,
                        reason: `Hostname Not Found: The hostname could not be found. The keycloak server is inaccessible at the specified URL. This might be due to a wrong host URL or DNS server issue.`,
                    };
                case 'EHOSTUNREACH':
                    return {
                        status: 404,
                        reason: `Hostname Not Found: The hostname could not be found. The keycloak server is inaccessible at the specified URL. This might be due to a wrong host URL or DNS server issue.`,
                    };
                default:

                    if ( err.response ) {

                        if ( typeof ( err.response.data ) === "object" ) {

                            return {
                                status: err.response.status,
                                reason: err.response.data.error
                            }
                        }

                        return {
                            status: err.response.status,
                            reason: err.response.data,
                        };
                    }
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
                                    reason: 'Invalid Client ID: The CLIENT_ID value is not valid in the keycloak configuration. Please provide a valid client id.',
                                };
                            case 'unauthorized_client':

                                return {
                                    status: err.response.status,
                                    reason: 'Invalid Client Secret: The CLIENT_SECRET (credentials.secret in keycloak Config) value is not valid in the keycloak configuration. Please provide a valid client secret.',
                                };
                            case 'Realm does not exist':

                                return {
                                    status: err.response.status,
                                    reason: 'Invalid Realm: The realm is not valid in the keycloak configuration. Please provide a valid Keycloak realm.',
                                };
                            case 'invalid_grant':

                                return {
                                    status: err.response.status,
                                    reason: 'Invalid User Credentials: The provided credentials are not valid. Please enter valid user credentials.',
                                };
                            default:

                                if ( typeof ( err.response.data ) === "object" ) {

                                    if ( err.response.status == 403 && err.response.data.error == 'unknown_error' ) {

                                        return {
                                            status: err.response.status,
                                            reason: 'Missing Admin Roles: Please make sure all the realm-management roles are assigned to admin user.',
                                        };

                                    }

                                    return {
                                        status: err.response.status,
                                        reason: err.response.data.error
                                    }
                                }

                                return {
                                    status: err.response.status,
                                    reason: err.response.data,
                                };

                        }

                    } else {

                        if ( typeof ( err.response.data ) === "object" ) {

                            return {
                                status: err.response.status,
                                reason: err.response.data.error
                            }
                        }

                        return {
                            status: err.response.status,
                            reason: err.response.data,
                        };

                    }

                }


            }

            return {
                status: 'ReferenceError',
                reason: "Variable or Function Error: A variable or function has not been declared or is out of scope."
            };
        }
    }
}

module.exports = ErrorService;