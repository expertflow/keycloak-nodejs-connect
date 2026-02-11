const https = require( 'https' );

let requestController = require( "../controller/requestController.js" );

class SalesforceService {


    async authenticateUserViaSalesforce( validationToken, salesforceUrl ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = salesforceUrl + '/services/oauth2/userinfo'


            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${validationToken}`
                },
                //disable ssl
                httpsAgent: new https.Agent( { rejectUnauthorized: false } )
            };

            try {

                let userInfoResponse = await requestController.httpRequest( config, false );
                let userObject = userInfoResponse?.data;


                resolve( {
                    'data': userObject,
                    'status': userInfoResponse?.status
                } );

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    reject( {
                        error_message: "Salesforce Authentication Error: An error occurred while validating user in Salesforce.",
                        error_detail: {
                            status: 408,
                            reason: `Salesforce server not accessible against URL: ${salesforceUrl}`
                        }
                    } )

                } else if ( er.response ) {

                    reject( {
                        error_message: "Salesforce Authentication Error: An error occurred while validating user in Salesforce.",
                        error_detail: {
                            status: er.response.status,
                            reason: er.response.statusText
                        }
                    } )

                }

            }

        } );
    }
}

module.exports = SalesforceService;
