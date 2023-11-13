let requestController = require( "../controller/requestController.js" );

class TeamsService {

    constructor () {

    }

    //This function is being used inside getUserSupervisedGroups()
    async getGroupByGroupID( groupId, username, token, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = keycloakConfig[ "auth-server-url" ] + 'admin/realms/' + keycloakConfig.realm + '/groups/' + groupId + '/';

            var config = {
                method: 'get',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                headers: {
                    'Authorization': 'Bearer ' + token
                }
            };

            try {

                let groupAttributes = await requestController.httpRequest( config, false );
                let attributes = groupAttributes.data.attributes;

                if ( attributes != null ) {

                    if ( 'supervisor' in attributes ) {

                        let supervisors = attributes[ 'supervisor' ][ 0 ].split( "," );

                        if ( supervisors.includes( username ) ) {

                            resolve( {
                                'teamId': groupAttributes.data.id,
                                'teamName': groupAttributes.data.name
                            } );
                        }
                    }
                }

                resolve( null );

            } catch ( error ) {

                reject( error );
            }

        } );
    }

    //this function is being used inside getTeamUsers()
    async getUsersOfGroups( groups, config, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            try {
                let allUsers = [];
                let rolesArr = [];

                if ( groups.length > 0 ) {

                    for ( let group of groups ) {

                        let id = null;
                        let name = null;

                        if ( typeof group === 'object' ) {
                            id = ( group.id ) ? group.id : group.teamId;
                            name = ( group.name ) ? group.name : group.teamName;
                        }

                        let URL = keycloakConfig[ "auth-server-url" ] + 'admin/realms/' + keycloakConfig.realm + '/groups/' + id + '/members';
                        config.url = URL;
                        let users = await requestController.httpRequest( config, true );

                        if ( users.data.length > 0 ) {

                            for ( let user of users.data ) {

                                try {

                                    let URL2 = keycloakConfig[ "auth-server-url" ] + 'admin/realms/' + keycloakConfig.realm + '/users/' + user.id + '/role-mappings';
                                    config.url = URL2;
                                    let rolesObj = await requestController.httpRequest( config, true );

                                    rolesArr = rolesObj.data.realmMappings.map( roles => {
                                        return roles.name;
                                    } );

                                } catch ( er ) {
                                    reject( er );
                                }

                                let isExist = ( allUsers ).find( x => x.username == user.username );

                                if ( !isExist ) {
                                    allUsers.push( {
                                        'id': user.id,
                                        'username': user.username,
                                        'firstName': ( user.firstName ) ? user.firstName : '',
                                        'lastName': ( user.lastName ) ? user.lastName : '',
                                        'realm': keycloakConfig.realm,
                                        'roles': rolesArr,
                                        'team': {
                                            'teamId': id,
                                            'teamName': name
                                        },
                                        'attributes': ( user.attributes ) ? user.attributes : {}
                                    } );
                                }

                            }

                        }

                    }

                    resolve( allUsers );
                }

                resolve( [] );

            } catch ( er ) {
                reject( er );
            }
        } );
    }

    async getGroupsList( token, keycloakConfig ) {
        return new Promise( async ( resolve, reject ) => {

            try {

                let URL = keycloakConfig[ "auth-server-url" ] + 'admin/realms/' + keycloakConfig.realm + '/groups';

                var config = {
                    method: 'get',
                    url: URL,
                    headers: {
                        'Accept': 'application/json',
                        'cache-control': 'no-cache',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                };

                try {

                    let groups = await requestController.httpRequest( config, false );
                    let groupsList = groups.data;

                    resolve( groupsList );

                } catch ( error ) {
                    reject( error );
                }
            } catch ( er ) {
                reject( "error" + er );
            };
        } );
    }

    async getUsersList( token, keycloakConfig ) {
        return new Promise( async ( resolve, reject ) => {

            try {

                let URL = keycloakConfig[ "auth-server-url" ] + 'admin/realms/' + keycloakConfig.realm + '/users?max=10000';

                var config = {
                    method: 'get',
                    url: URL,
                    headers: {
                        'Accept': 'application/json',
                        'cache-control': 'no-cache',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                };

                try {

                    let users = await requestController.httpRequest( config, false );
                    let usersList = users.data;

                    resolve( usersList );

                } catch ( error ) {
                    reject( error );
                }
            } catch ( er ) {
                reject( "error" + er );
            };
        } );
    }

    async addSupervisorToGroup( supervisedGroups, token, keycloakConfig ) {

        let updatedGroups;

        return new Promise( async ( resolve, reject ) => {

            try {

                supervisedGroups.forEach( async group => {

                    let URL = keycloakConfig[ "auth-server-url" ] + 'admin/realms/' + keycloakConfig.realm + '/groups/' + group.id;

                    var config = {
                        method: 'put',
                        url: URL,
                        headers: {
                            'Accept': 'application/json',
                            'cache-control': 'no-cache',
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        headers: {
                            'Authorization': 'Bearer ' + token
                        },
                        data: {
                            name: group.name,
                            attributes: group.attributes
                        }
                    };

                    try {

                        let groups = await requestController.httpRequest( config, false );

                    } catch ( error ) {
                        reject( error );
                    }
                } );

                resolve( 'Supervisors Added' );

            } catch ( er ) {
                reject( "error" + er );
            };
        } );
    }
}

module.exports = TeamsService;