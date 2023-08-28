

class ErrorService {

    constructor () {

    }

    async handleError( err ) {

        if ( err.code == "ETIMEDOUT" ) {

            return {
                "Keycloak login status": 408,
                "keycloak login message": `Keycloak server unaccessable against URL: ${keycloakConfig[ "auth-server-url" ]}`,
            };

        } else {

            if ( err.response ) {
                return {
                    status: err.response.status,
                    reason: err.response.data,
                };
            }

            return err;
        }
    }
}

module.exports = ErrorService;