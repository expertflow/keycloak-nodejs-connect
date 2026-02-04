const parseXMLString = require( 'xml2js' ).parseString;
const https = require( 'https' );

let requestController = require( "../controller/requestController.js" );

class Dynamics365Service {


    async authenticateUserViaDynamics365( validationToken, dynamics365Url ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = dynamics365Url + '/WhoAmI'


            let config = {
                method: 'get',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'OData-MaxVersion': '4.0',
                'OData-Version': '4.0',
                url: URL,
                headers: {
                    'Authorization': `Bearer ${validationToken}`
                },
                //disable ssl
                httpsAgent: new https.Agent( { rejectUnauthorized: false } )
            };

            try {

                let whoAmIResponse = await requestController.httpRequest( config, false );

                let userId = whoAmIResponse?.data?.UserId;

                try {

                    let URL1 = `${dynamics365Url}/systemusers(${userId})?$select=fullname,firstname,middlename,lastname,internalemailaddress,title,isdisabled,businessunitid,mobilephone,createdon,modifiedon`
                    config.url = URL1;
                    config.maxBodyLength = 'Infinity';

                    let userObjectResponse = await requestController.httpRequest( config, true );
                    let userObject = userObjectResponse?.data;


                    resolve( {
                        'data': userObject,
                        'status': userObjectResponse?.status
                    } );

                }
                catch ( er ) {

                    if ( er.code == "ENOTFOUND" ) {

                        reject( {
                            error_message: "Dynamics365 Authentication Error: An error occurred while getting the user data from Dynamics365.",
                            error_detail: {
                                status: 408,
                                reason: `Dynamics365 server not accessible against URL: ${dynamics365Url}`
                            }
                        } )

                    } else if ( er.response ) {

                        reject( {
                            error_message: "Dynamics365 Authentication Error: An error occurred while getting the user data from Dynamics365.",
                            error_detail: {
                                status: er.response.status,
                                reason: er.response.statusText
                            }
                        } )

                    }

                }

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    reject( {
                        error_message: "Dynamics365 Authentication Error: An error occurred while validating user in Dynamics365.",
                        error_detail: {
                            status: 408,
                            reason: `Finesse server not accessible against URL: ${dynamics365Url}`
                        }
                    } )

                } else if ( er.response ) {

                    reject( {
                        error_message: "Dynamics365 Authentication Error: An error occurred while validating user in Dynamics365.",
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

module.exports = Dynamics365Service;
