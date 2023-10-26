const parseXMLString = require( 'xml2js' ).parseString;
const https = require( 'https' );

var requestController = require( "../controller/requestController.js" );

class FinesseService {

    constructor () {

    }


    async authenticateUserViaFinesse( username, password, finesseUrl ) {

        return new Promise( async ( resolve, reject ) => {

            var URL = finesseUrl + '/finesse/api/User/' + username;
            let userObject = {};

            let encodedCredentials = await this.maskCredentials( username, password );

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Basic ${encodedCredentials}`
                },
                //disable ssl
                httpsAgent: new https.Agent( { rejectUnauthorized: false } )
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );

                parseXMLString( tokenResponse.data, async ( err, result ) => {

                    if ( err ) {
                        console.error( err );
                    } else {
                        if ( result.User ) {

                            let user = result.User;

                            userObject = {
                                username: user.loginName[ 0 ],
                                firstName: user.firstName[ 0 ],
                                lastName: user.lastName[ 0 ],
                                roles: ( user.roles[ 0 ].role ).map( role => role.toLowerCase() ),
                                group: ( user.teamName == '' || user.teamName == null ) ? [ 'default' ] : { id: user.teamId[ 0 ], name: user.teamName[ 0 ] }
                            }

                            if ( user.teams ) {

                                if ( user.teams[ 0 ].Team ) {

                                    userObject.supervisedGroups = ( user.teams[ 0 ].Team ).map( team => {
                                        return {
                                            id: team.id[ 0 ],
                                            name: team.name[ 0 ]
                                        }
                                    } );
                                }
                            }
                        }
                    }
                }
                );

                resolve( {
                    'data': userObject,
                    'status': tokenResponse.status
                } );

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    reject( {
                        error_message: "Error Occured While Authenticating User Via Finesse",
                        error_detail: {
                            status: 408,
                            reason: `finesse server not accessible against URL: ${finesseUrl}`
                        }
                    } )

                } else if ( er.response ) {

                    reject( {
                        error_message: "Error Occured While Authenticating User Via Finesse",
                        error_detail: {
                            status: er.response.status,
                            reason: er.response.statusText
                        }
                    } )

                }

            }

        } );
    }

    async authenticateUserViaFinesseSSO( username, finesseToken, finesseUrl ) {

        return new Promise( async ( resolve, reject ) => {

            var URL = finesseUrl + '/finesse/api/User/' + username;

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Bearer ${finesseToken}`
                },
                //disable ssl
                httpsAgent: new https.Agent( { rejectUnauthorized: false } )
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );

                resolve( {
                    'status': tokenResponse.status
                } );

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    reject( {
                        error_message: "Error Occured While Authenticating User Via Finesse SSO",
                        error_detail: {
                            status: 408,
                            reason: `finesse server not accessible against URL: ${finesseUrl}`
                        }
                    } )

                } else if ( er.response ) {

                    reject( {
                        error_message: "Error Occured While Authenticating User Via Finesse SSO",
                        error_detail: {
                            status: er.response.status,
                            reason: er.response.statusText
                        }
                    } )

                }
            }

        } );
    }

    async getCiscoTeams( username, password, finesseUrl ) {

        return new Promise( async ( resolve, reject ) => {

            var URL = finesseUrl + '/finesse/api/Teams';

            let encodedCredentials = await this.maskCredentials( username, password );

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Basic ${encodedCredentials}`
                },
                //disable ssl
                httpsAgent: new https.Agent( { rejectUnauthorized: false } )
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );

                resolve( tokenResponse.data );

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    resolve( {
                        'finesse login status': 408,
                        'finesse login message': `finesse server not accessible against URL: ${finesseUrl}`
                    } );

                } else if ( er.response ) {

                    resolve( {
                        'finesse login status': er.response.status,
                        'finesse login message': er.response.statusText
                    } );

                }

            }

        } );
    }

    async getCiscoUsers( username, password, finesseUrl ) {

        return new Promise( async ( resolve, reject ) => {

            var URL = finesseUrl + '/finesse/api/Users';

            let encodedCredentials = await this.maskCredentials( username, password );

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Basic ${encodedCredentials}`
                },
                //disable ssl
                httpsAgent: new https.Agent( { rejectUnauthorized: false } )
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );

                resolve( tokenResponse.data );

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    resolve( {
                        'finesse login status': 408,
                        'finesse login message': `finesse server not accessible against URL: ${finesseUrl}`
                    } );

                } else if ( er.response ) {

                    resolve( {
                        'finesse login status': er.response.status,
                        'finesse login message': er.response.statusText
                    } );

                }

            }

        } );
    }

    async maskCredentials( username, password ) {

        let token = Buffer.from( `${username}:${password}`, 'utf8' ).toString( 'base64' );
        return token;

    }
}

module.exports = FinesseService;