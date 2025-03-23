const parseXMLString = require( 'xml2js' ).parseString;
const https = require( 'https' );

let requestController = require( "../controller/requestController.js" );
const ErrorService = require( './errorService.js' );
const { copyFileSync } = require( 'fs' );

const errorService = new ErrorService();
let realmRoles = [];

// ===================== Class Definition =====================
class CiscoSyncService {

    constructor () {

    }

    // ===================== Team Sync =====================

    async createCXTeam( ciscoTeam, cxURL ) {

        return new Promise( async ( resolve, reject ) => {

            //Setting URL to Create CX team
            let URL = `${cxURL}team`;

            const teamData = {
                "team_Id": ciscoTeam.id,
                "team_name": ciscoTeam.name,
                "supervisor_Id": "",
                "source": "CISCO",
                "created_by": "1"
            };

            let config = {

                method: "post",
                headers: {
                    Accept: "application/json",
                    "cache-control": "no-cache",
                    "Content-Type": "application/json",
                },
                url: URL,
                data: teamData

            };

            try {

                //Creating CX team
                let createCXTeam = await requestController.httpRequest( config, false );
                resolve( createCXTeam.data );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "Finesse Team Sync Error: Error occured while creating cx core team.",
                    error_detail: error
                } );
            }
        } );
    }

    async updateCXTeam( ciscoTeam, teamData, cxURL ) {

        return new Promise( async ( resolve, reject ) => {

            //Setting URL to Update CX team of Agent
            let URL = `${cxURL}team/${teamData.team_Id}`;

            //updating name of cx team to cisco team.
            teamData.team_name = ciscoTeam.name;


            let config = {

                method: "put",
                headers: {
                    Accept: "application/json",
                    "cache-control": "no-cache",
                    "Content-Type": "application/json",
                },
                url: URL,
                data: teamData

            };

            try {

                //Updating CX team
                let updateCXTeam = await requestController.httpRequest( config, false );
                resolve( updateCXTeam.data );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "Finesse Team Sync Error: Error occured while updating cx core team.",
                    error_detail: error
                } );
            }
        } );
    }

    async syncTeamsToCX( ciscoTeams, cxTeams, cxURL ) {


        // Create a map of CX teams by their ID for fast lookup
        const cxTeamMap = new Map();

        cxTeams.forEach( ( team ) => {

            if ( team.source === 'CISCO' ) {
                cxTeamMap.set( team.team_Id, team );
            }
        } );

        //testing with only 2 teams for now
        //ciscoTeams = ciscoTeams.slice( 0, 2 );

        // Iterate over Cisco teams and sync them with CX
        for ( let ciscoTeam of ciscoTeams ) {

            const cxTeam = cxTeamMap.get( ciscoTeam.id );

            if ( !cxTeam ) {

                await this.createCXTeam( ciscoTeam, cxURL );

            } else if ( cxTeam.team_name !== ciscoTeam.name ) {

                // Team exists but name changed, update it
                await this.updateCXTeam( ciscoTeam, cxTeam, cxURL );
            }
        }
    }

    // ===================== User Sync =====================

    async syncUsersToCX( ciscoUsers, keycloakUsers, keycloakUsersByRole, keycloakUsersByPermissionGroups, keycloakConfig, adminToken ) {

        // Step 1: Create a Map of Keycloak users for fast lookup
        const keycloakUsersMap = new Map( keycloakUsers.map( user => [ user.username.toLowerCase(), user ] ) );

        // Step 2: Create a Set of Cisco usernames for fast lookup
        const ciscoUsernames = new Set( ciscoUsers.map( user => user.username.toLowerCase() ) );

        // Step 3: Filter out Keycloak users who have 'CISCO' in the 'type' attribute but are not in Cisco users list
        const usersToDisable = keycloakUsers.filter( user => {

            return user?.attributes?.type?.includes( 'CISCO' ) && !ciscoUsernames.has( user.username.toLowerCase() ) && user.enabled;
        } );

        // Step 4: Disable all the users that are not in Cisco users list and have type: CISCO
        for ( let user of usersToDisable ) {

            await this.updateKeycloakUser( [], user, keycloakConfig, adminToken );
        }

        // Step 5: Process Cisco users (create or update)
        for ( let ciscoUser of ciscoUsers ) {

            const keycloakUser = keycloakUsersMap.get( ciscoUser.username.toLowerCase() );
            const roles = ciscoUser.roles.map( role => role.toLowerCase() );

            if ( keycloakUser ) {

                // User exists, check for changes
                const userUpdated = await this.checkAndUpdateKeycloakUser( keycloakUser, ciscoUser, roles );

                if ( userUpdated ) {
                    await this.updateKeycloakUser( ciscoUser, keycloakUser, keycloakConfig, adminToken );
                }

                // Check if the user needs roles assigned
                await this.updateRolesInKeycloak( ciscoUser, keycloakUsersByRole, keycloakUsersByPermissionGroups, keycloakUser.id, adminToken, keycloakConfig );

            } else {

                // User doesn't exist in Keycloak, create the user
                await this.createKeycloakUser( ciscoUser, roles, keycloakConfig, adminToken );
            }
        }
    }


    async checkAndUpdateKeycloakUser( keycloakUser, ciscoUser, roles ) {
        // Compare first name, last name, extension
        let updated = false;

        if ( keycloakUser.firstName !== ciscoUser.firstName
            || keycloakUser.lastName !== ciscoUser.lastName
            || ( keycloakUser.attributes.user_name && ciscoUser.loginName !== keycloakUser.attributes.user_name[ 0 ] )
            || ( keycloakUser.attributes.extension && ciscoUser.extension !== keycloakUser.attributes.extension[ 0 ] )
            || ( !( keycloakUser.attributes.type ) || keycloakUser.attributes?.type?.[ 0 ] !== 'CISCO' )
        ) {
            updated = true;
        }

        // If any of the attributes are updated, return true
        return updated;
    }

    async createKeycloakUser( ciscoUser, roles, keycloakConfig, adminToken ) {

        let assignRole = [];
        let assignGroups = [];

        assignGroups = roles.includes( "supervisor" ) ? [ "agents_permission", "senior_agents_permission" ] : [ "agents_permission" ];


        return new Promise( async ( resolve, reject ) => {

            let URL = `${keycloakConfig[ "auth-server-url" ]}admin/realms/${keycloakConfig[ "realm" ]}/users`;

            let data = {

                username: ciscoUser.username,
                firstName: ciscoUser.firstName,
                lastName: ciscoUser.lastName,
                enabled: true,
                credentials: [
                    {
                        type: "password",
                        value: "Expertflow464",
                        temporary: false,
                    },
                ],
                attributes: {
                    "user_name": `${ciscoUser.loginName}`,
                    "extension": `${ciscoUser.extension}`,
                    "type": "CISCO"
                },
                groups: assignGroups
            };

            let config = {

                method: "post",
                url: URL,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`,
                },
                data: data,

            };

            try {

                let newUser = await requestController.httpRequest( config, false );

                //Get the user id at time of creation
                let userLocation = newUser.headers.location;
                let userLocationSplit = userLocation.split( "/" );
                let userId = userLocationSplit[ userLocationSplit.length - 1 ];

                //Get list of all the roles in keycloak realm
                /* Storing all the realm roles in Global realmRoles list.If some role come from finesse which doesn't
                exist in realmRoles list then we call keycloak roles api again to update realmRoles list. */
                if ( ciscoUser.roles != [] ) {

                    if ( realmRoles.length > 0 ) {

                        let check = checkForMissingRole( realmRoles, ciscoUser.roles );

                        if ( !check ) {

                            realmRoles = await this.getRealmRoles( adminToken, keycloakConfig );
                        }

                    } else {

                        realmRoles = await this.getRealmRoles( adminToken, keycloakConfig );
                    }

                    //checking whether role exist in realmRoles object array:
                    for ( let role of realmRoles ) {

                        ciscoUser.roles.forEach( ( userRole ) => {

                            if ( role.name == userRole.toLocaleLowerCase() ) {

                                assignRole.push( {
                                    id: role.id,
                                    name: role.name,
                                } );
                            }
                        } );
                    }

                    try {

                        //assigning role to user
                        let roleAssigned = await this.assignRoleToUser( userId, assignRole, adminToken, keycloakConfig );

                    } catch ( er ) {

                        let error = await errorService.handleError( er );

                        reject( {

                            error_message: "Role Assignment Error: An error occurred while assigning the role to the user in the Finesse user creation component.",
                            error_detail: error
                        } );
                    }
                }


                resolve( newUser );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "User Creation Error: An error occurred while creating the user in the Finesse user creation component.",
                    error_detail: error
                } );
            }

        } );
    }

    async updateKeycloakUser( ciscoUser, keycloakUser, keycloakConfig, adminToken ) {


        /* 
                Check for changes in user role, if user is removed from supervisor role then delete all its Permissions/Policies.
                If supervisor is added to user role then check for the groups it is supervising and create its permissions.
            
           
                Check for changes in user groups, if it is removed from one group as an agent and added to other group then remove
                user from old group and add to new group
           
           
                Check for teams user is supervising, if user is assigned new teams to supervise then create its permission/policy, if
                user is removed from supervising certain teams then remove its permissions from that team.
          */

        return new Promise( async ( resolve, reject ) => {

            let data = {};

            if ( Object.keys( ciscoUser ).length > 0 ) {

                data = {
                    firstName: ciscoUser.firstName,
                    lastName: ciscoUser.lastName,
                    attributes: {
                        "user_name": `${ciscoUser.loginName}`,
                        "extension": `${ciscoUser.extension}`,
                        "type": "CISCO"
                    }
                };
            } else {

                data = {
                    enabled: false
                }
            }



            if ( Object.keys( data ).length > 0 ) {


                let URL = `${keycloakConfig[ "auth-server-url" ]}admin/realms/${keycloakConfig[ "realm" ]}/users/${keycloakUser.id}`;

                let config = {

                    method: "put",
                    url: URL,
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${adminToken}`,
                    },
                    data: data,

                };

                try {

                    let updatedUser = await requestController.httpRequest( config, false );
                    resolve( updatedUser.data );


                } catch ( err ) {

                    let error = await errorService.handleError( err );

                    reject( {

                        error_message: "User Info Update Error: An error occurred while updating user information during the Cisco user sync process.",
                        error_detail: error
                    } );

                }

            } else {

                resolve( [] );
            }

        } );
    }

    async updateRolesInKeycloak( ciscoUser, keycloakUsersByRole, keycloakUsersByPermissionGroups, keycloakUserId, adminToken, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            let rolesToAdd = [];
            let rolesToRemove = [];
            let groupsToAdd = [];
            let groupsToRemove = [];

            //Updating group data in case it is not similar.
            let finesseGroups = ciscoUser.roles.includes( "supervisor" ) ? [ "agents_permission", "senior_agents_permission" ] : [ "agents_permission" ];

            // Loop through all roles in keycloakUsersByRole
            for ( const role in keycloakUsersByRole ) {

                if ( keycloakUsersByRole.hasOwnProperty( role ) ) {

                    const roleSet = new Set( keycloakUsersByRole[ role ].map( user => user.username ) );

                    // Check if user should have this role
                    if ( roleSet.has( ( ciscoUser.username ).toLowerCase() ) && !ciscoUser.roles.includes( role ) ) {

                        rolesToRemove.push( role ); // Role should be removed if user has it but doesn't need it
                    }

                    // Check if user is missing this role
                    if ( !roleSet.has( ( ciscoUser.username ).toLowerCase() ) && ciscoUser.roles.includes( role ) ) {

                        rolesToAdd.push( role ); // Role should be added if user needs it
                    }

                    //user has role but dont have permission groups
                    if ( roleSet.has( ( ciscoUser.username ).toLowerCase() ) ) {

                        if ( role === 'agent' && !keycloakUsersByPermissionGroups[ 'agents_permission' ].some( user => user.username.toLowerCase() === ciscoUser.username.toLowerCase() ) && ciscoUser.roles.includes( role ) ) {

                            groupsToAdd.push( keycloakUsersByPermissionGroups[ 'agents_permission' ][ 0 ].groupId );

                        } else if ( role === 'supervisor' && !keycloakUsersByPermissionGroups[ 'senior_agents_permission' ].some( user => user.username.toLowerCase() === ciscoUser.username.toLowerCase() ) && ciscoUser.roles.includes( role ) ) {

                            console.log( role );
                            groupsToAdd.push( keycloakUsersByPermissionGroups[ 'senior_agents_permission' ][ 0 ].groupId );
                        }
                    }
                }
            }

            try {

                // Step 3: Check if the user should have the appropriate permission groups
                // Check if 'agents_permission' or 'senior_agents_permission' should be added for this user
                if ( rolesToAdd.includes( "agent" ) && !keycloakUsersByPermissionGroups[ 'agents_permission' ].some( user => user.username.toLowerCase() === ciscoUser.username.toLowerCase() ) ) {

                    groupsToAdd.push( keycloakUsersByPermissionGroups[ 'agents_permission' ][ 0 ].groupId );
                }

                if ( rolesToAdd.includes( "supervisor" ) ) {

                    // Add 'agents_permission' and 'senior_agents_permission' if they are not already in the user's groups
                    if ( !keycloakUsersByPermissionGroups[ 'agents_permission' ].some( user => user.username.toLowerCase() === ciscoUser.username.toLowerCase() ) ) {

                        groupsToAdd.push( keycloakUsersByPermissionGroups[ 'agents_permission' ][ 0 ].groupId );
                    }
                    if ( !keycloakUsersByPermissionGroups[ 'senior_agents_permission' ].some( user => user.username.toLowerCase() === ciscoUser.username.toLowerCase() ) ) {

                        groupsToAdd.push( keycloakUsersByPermissionGroups[ 'senior_agents_permission' ][ 0 ].groupId );
                    }
                }

                // Step 4: Remove groups if the user is no longer supposed to have them
                if ( rolesToRemove.includes( "supervisor" ) && keycloakUsersByPermissionGroups[ 'senior_agents_permission' ].some( user => user.username.toLowerCase() === ciscoUser.username.toLowerCase() ) ) {

                    groupsToRemove.push( keycloakUsersByPermissionGroups[ 'senior_agents_permission' ][ 0 ].groupId );
                }

                // Step 5: Add or remove the groups in Keycloak based on the modifications
                if ( groupsToAdd.length > 0 ) {

                    await this.addOrRemoveUserGroup( keycloakUserId, groupsToAdd, 'add', adminToken, keycloakConfig );
                }

                if ( groupsToRemove.length > 0 ) {

                    await this.addOrRemoveUserGroup( keycloakUserId, groupsToRemove, 'remove', adminToken, keycloakConfig );
                }

            } catch ( err ) {

                console.log( err );
                let error = await errorService.handleError( err );

                reject( {

                    error_message: "User Group Assignment Error, Error occurred while updating permission groups of user during user update process.",
                    error_detail: error
                } );

            }

            try {

                if ( rolesToAdd.length > 0 || rolesToRemove.length > 0 ) {

                    const rolesPromises = [];

                    if ( rolesToAdd.length > 0 ) {

                        let addRolesPromise = this.addOrRemoveUserRole( keycloakUserId, rolesToAdd, 'add', adminToken, keycloakConfig );
                        rolesPromises.push( addRolesPromise );
                    }

                    if ( rolesToRemove.length > 0 ) {

                        let removeRolesPromise = this.addOrRemoveUserRole( keycloakUserId, rolesToRemove, 'remove', adminToken, keycloakConfig );
                        rolesPromises.push( removeRolesPromise );
                    }

                    // Wait for all promises to complete before moving on
                    await Promise.all( rolesPromises );
                    resolve( [] );

                } else {

                    resolve( [] );
                }
            } catch ( err ) {

                let error = await errorService.handleError( err );

                reject( {

                    error_message: "User Role Assignment Error, Error occurred while updating roles of user during user update process.",
                    error_detail: error
                } );

            }
        } );

    }


    // ===================== Main Function to Sync Everything =====================
    async syncCiscoData( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL, keycloakConfig, adminToken ) {

        return new Promise( async ( resolve, reject ) => {

            try {

                let ciscoUsers = [];
                // Step 1: Fetch the Cisco and CX data for users and teams

                //Fetch Cisco Teams
                let ciscoTeams = await this.fetchCiscoTeams( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL );

                //Fetch Cisco Users
                ciscoUsers = await this.fetchCiscoUsers( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL );

                //Fetch CX Team
                let cxTeams = await this.fetchCXTeams( keycloakConfig[ "ef-server-url" ] );

                // Fetch Keycloak users
                let keycloakUsers = await this.fetchKeycloakUsers( keycloakConfig[ "auth-server-url" ], adminToken );
                const keycloakUsersByRole = await this.fetchKeycloakUsersByRole( keycloakConfig[ "auth-server-url" ], adminToken );
                const keycloakUsersByPermissionGroups = await this.fetchKeycloakUsersByPermissionGroups( keycloakConfig, adminToken );

                if ( ciscoUsers.length > 0 && ciscoTeams.length > 0 ) {

                    // Step 2: Sync Teams to CX
                    await this.syncTeamsToCX( ciscoTeams, cxTeams, keycloakConfig[ "ef-server-url" ] );

                    // Step 3: Sync Users to CX (only after teams are synced)
                    await this.syncUsersToCX( ciscoUsers, keycloakUsers, keycloakUsersByRole, keycloakUsersByPermissionGroups, keycloakConfig, adminToken );

                    //Once users are synced, we fetch updated keycloak users list.
                    keycloakUsers = await this.fetchKeycloakUsers( keycloakConfig[ "auth-server-url" ], adminToken );
                    console.log( keycloakUsers.map( user => {
                        return {
                            id: user.id,
                            username: user.username
                        }
                    } ) );

                    const ciscoUsernames = ciscoUsers.map( user => user.username.toLowerCase() );
                    let uniqueKeycloakUsers = keycloakUsers.filter( user => !ciscoUsernames.includes( user.username.toLowerCase() ) );

                    uniqueKeycloakUsers = uniqueKeycloakUsers.map( user => {
                        return {
                            id: user.id,
                            username: user.username
                        }
                    } );

                    // Step 4: Assign Users to Teams
                    let ciscoTeamsIds = ciscoTeams.map( team => Number( team.id ) );
                    const cxTeamsMembers = await this.fetchCXTeamsMembers( keycloakConfig[ "ef-server-url" ], ciscoTeamsIds );


                    let { agentsToAdd, agentsToRemove, supervisorsToAdd,
                        supervisorsToRemove } = this.addOrRemoveAgentsOrSupervisors( ciscoUsers, cxTeamsMembers, keycloakUsers, uniqueKeycloakUsers );

                    const { cxAgents, cxSupervisors } = this.mapTeamMembersToKeycloak( ciscoTeams, cxTeamsMembers, uniqueKeycloakUsers );


                    //Remove Agents from wrong Teams (both CX and Cisco)
                    ( Object.keys( agentsToRemove ).length > 0 ) && await this.removeAgentsFromTeams( keycloakConfig[ "ef-server-url" ], agentsToRemove );
                    ( Object.keys( cxAgents ).length > 0 ) && await this.removeAgentsFromTeams( keycloakConfig[ "ef-server-url" ], cxAgents );

                    //Add Agents To Team
                    ( Object.keys( agentsToAdd ).length > 0 ) && await this.addAgentsToTeams( keycloakConfig[ "ef-server-url" ], agentsToAdd );

                    //Remove Primary Supervisors from wrong Team (both CX and Cisco)
                    ( Object.keys( supervisorsToRemove.primary ).length > 0 ) && await this.removePrimarySupervisorsFromTeams( keycloakConfig[ "ef-server-url" ], supervisorsToRemove.primary );

                    ( Object.keys( cxSupervisors.primary ).length > 0 ) && await this.removePrimarySupervisorsFromTeams( keycloakConfig[ "ef-server-url" ], cxSupervisors.primary );

                    //Remove Secondary Supervisors from wrong Team (both CX and Cisco)
                    ( Object.keys( supervisorsToRemove.secondary ).length > 0 ) && await this.removeSecondarySupervisorsFromTeams( keycloakConfig[ "ef-server-url" ], supervisorsToRemove.secondary );

                    ( Object.keys( cxSupervisors.secondary ).length > 0 ) && await this.removeSecondarySupervisorsFromTeams( keycloakConfig[ "ef-server-url" ], cxSupervisors.secondary );

                    //Add Primary Supervisors to Team
                    ( Object.keys( supervisorsToAdd.primary ).length > 0 ) && await this.addPrimarySupervisorsToTeams( keycloakConfig[ "ef-server-url" ], supervisorsToAdd.primary );

                    //Add Secondary Supervisors To Team
                    ( Object.keys( supervisorsToAdd.secondary ).length > 0 ) && await this.addSecondarySupervisorsToTeams( keycloakConfig[ "ef-server-url" ], supervisorsToAdd.secondary );

                    resolve( 'Data synchronization complete!' );

                } else {

                    reject( {

                        error_message: "Error occurred while Syncing Cisco Data in Keycloak and CX",
                        error_detail: "There are no Teams or Users on Cisco Side, Please add Teams/Users to Sync on CX"
                    } );
                }

            } catch ( er ) {

                if ( er.error_message ) {

                    reject( {

                        error_message: "Error occurred while Syncing Cisco Data in Keycloak and CX",
                        error_detail: er
                    } );

                } else {

                    let error = await errorService.handleError( er );

                    reject( {

                        error_message: "Error occurred while Syncing Cisco Data in Keycloak and CX",
                        error_detail: error
                    } );
                }


            }

        } );
    }

    // ===================== Helper Functions =====================

    // ===================== Teams Sync Helper Functions ===============
    async fetchCiscoTeams( username, password, finesseUrl ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = finesseUrl + '/finesse/api/Teams?nocache=1680864072911&bypassServerCache=true';
            let teamsObject;

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

                        teamsObject = result.Teams.Team.map( team => ( {
                            id: team.id[ 0 ],
                            name: team.name[ 0 ]
                        } ) );
                    }
                }
                );

                resolve( teamsObject );

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    reject( {
                        error_message: "Finesse Authentication Error: An error occurred while fetching finesse teams list.",
                        error_detail: {
                            status: 408,
                            reason: `Finesse server not accessible against URL: ${finesseUrl}`
                        }
                    } )

                } else if ( er.response ) {

                    reject( {
                        error_message: "Finesse Authentication Error: An error occurred while fetching finesse teams list.",
                        error_detail: {
                            status: er.response.status,
                            reason: er.response.statusText
                        }
                    } )

                }

            }

        } );
    }

    async fetchCXTeams( cxURL ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = cxURL + 'team';

            let config = {
                method: 'get',
                url: URL
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );

                // Filter the teams to only include those with source: "CISCO"
                let filteredTeams = tokenResponse.data.filter( team => team.source === 'CISCO' );

                resolve( filteredTeams );

            }
            catch ( er ) {

                reject( er );
            }
        } )
    }

    async fetchCXTeamsMembers( cxURL, teamIdsArr ) {

        return new Promise( async ( resolve, reject ) => {

            teamIdsArr = teamIdsArr.join( ',' );
            let URL = `${cxURL}team/member?teamIds=${teamIdsArr}`;

            let config = {
                method: 'get',
                url: URL
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );

                resolve( tokenResponse.data );

            }
            catch ( er ) {

                reject( er );
            }
        } )
    }

    // ===================== Users Sync Helper Functions ===============
    async fetchCiscoUsers( username, password, finesseUrl ) {


        return new Promise( async ( resolve, reject ) => {

            let URL = finesseUrl + '/finesse/api/Users';
            let userslistObject;

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

                        userslistObject = result.Users.User.map( user => ( {
                            username: user.loginId[ 0 ],
                            loginName: user.loginName[ 0 ],
                            firstName: user.firstName[ 0 ],
                            lastName: user.lastName[ 0 ],
                            extension: user.extension[ 0 ],
                            roles: ( user.roles[ 0 ].role ).map( role => role.toLowerCase() ),
                            team: ( user.teamName == '' || user.teamName == null ) ? [ 'default' ] : { id: user.teamId[ 0 ], name: user.teamName[ 0 ] },
                            supervisedTeams: ( user.teams && user.teams[ 0 ].Team ) ?
                                user.teams[ 0 ].Team.map( team => ( {
                                    id: team.id[ 0 ],
                                    name: team.name[ 0 ]
                                } ) ) : []
                        } ) );


                        resolve( userslistObject );
                    }
                }
                );

                resolve( [] );

            }
            catch ( er ) {

                if ( er.code == "ENOTFOUND" ) {

                    reject( {
                        error_message: "Finesse Authentication Error: An error occurred while fetching finesse users list.",
                        error_detail: {
                            status: 408,
                            reason: `Finesse server not accessible against URL: ${finesseUrl}`
                        }
                    } )

                } else if ( er.response ) {

                    reject( {
                        error_message: "Finesse Authentication Error: An error occurred while fetching finesse users list",
                        error_detail: {
                            status: er.response.status,
                            reason: er.response.statusText
                        }
                    } )

                }

            }

        } );
    }

    async fetchKeycloakUsers( keycloakURL, adminToken ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = keycloakURL + 'admin/realms/expertflow/users?max=100000';

            let config = {

                method: "get",
                url: URL,
                headers: {
                    Accept: "application/json",
                    "cache-control": "no-cache",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                headers: {
                    Authorization: "Bearer " + adminToken,
                },

            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );
                resolve( tokenResponse.data );

            } catch ( er ) {

                reject( er );
            }
        } )
    }

    async fetchKeycloakUsersByRole( keycloakURL, adminToken ) {

        return new Promise( async ( resolve, reject ) => {

            let usersAgainstRoles = {};

            let roles = [ 'agent', 'supervisor' ];

            // Use Promise.all to handle multiple role requests concurrently
            for ( let role of roles ) {

                const URL = `${keycloakURL}admin/realms/expertflow/roles/${role}/users?max=1000000`;

                const config = {
                    method: "get",
                    url: URL,
                    headers: {
                        Accept: "application/json",
                        "cache-control": "no-cache",
                        "Content-Type": "application/x-www-form-urlencoded",
                        Authorization: `Bearer ${adminToken}`,
                    },
                };

                try {

                    const tokenResponse = await requestController.httpRequest( config, true );
                    usersAgainstRoles[ role ] = tokenResponse.data
                        .map( user => (
                            user?.attributes?.type?.[ 0 ] === 'CISCO' ? {
                                id: user.id,
                                username: user.username
                            } : null
                        ) )
                        .filter( user => user !== null );

                } catch ( err ) {

                    reject( err );
                }
            }

            resolve( usersAgainstRoles );

        } );
    }

    async fetchKeycloakUsersByPermissionGroups( keycloakConfig, adminToken ) {

        return new Promise( async ( resolve, reject ) => {

            let usersAgainstPermissionGroups = {};

            let permissionGroups = [ 'agents_permission', 'senior_agents_permission' ];
            let permissionGroupsObj = await this.gettingGroupByGroupName( permissionGroups, adminToken, keycloakConfig );

            if ( permissionGroupsObj.length > 0 ) {


                // Use Promise.all to handle multiple role requests concurrently
                for ( let group of permissionGroupsObj ) {

                    const URL = `${keycloakConfig[ "auth-server-url" ]}admin/realms/expertflow/groups/${group.id}/members?max=1000000`;

                    const config = {

                        method: "get",
                        url: URL,
                        headers: {
                            Accept: "application/json",
                            "cache-control": "no-cache",
                            "Content-Type": "application/x-www-form-urlencoded",
                            Authorization: `Bearer ${adminToken}`,
                        },
                    };

                    try {

                        const tokenResponse = await requestController.httpRequest( config, true );

                        usersAgainstPermissionGroups[ group.name ] = tokenResponse.data
                            .map( user => (
                                user?.attributes?.type?.[ 0 ] === 'CISCO' ? {
                                    id: user.id,
                                    username: user.username,
                                    groupId: group.id
                                } : null
                            ) )
                            .filter( user => user !== null );

                    } catch ( err ) {

                        reject( err );
                    }
                }

            }

            resolve( usersAgainstPermissionGroups );

        } );
    }

    async getRealmRoles( adminToken, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = `${keycloakConfig[ "auth-server-url" ]}admin/realms/${keycloakConfig[ "realm" ]}/roles`;

            let config = {
                method: "get",
                url: URL,
                headers: {
                    Authorization: `Bearer ${adminToken}`,
                },
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, false );
                resolve( tokenResponse.data );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "Realm Roles Fetch Error: An error occurred while fetching realm roles.",
                    error_detail: error
                } );

            }
        } );
    }

    async assignRoleToUser( userId, roles, adminToken, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users/${userId}/role-mappings/realm`;

            let config = {
                method: "post",
                url: URL,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`,
                },
                data: roles,
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, false );
                resolve( tokenResponse );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "Role Assignment Error: An error occurred while assigning the role to the user.",
                    error_detail: error
                } );
            }
        } );
    }

    async addOrRemoveUserRole( userId, roles, operation, token, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            let method = ( operation == 'remove' ) ? 'delete' : 'post';

            if ( realmRoles.length > 0 ) {

                let check = checkForMissingRole( realmRoles, roles );

                if ( !check ) {

                    realmRoles = await this.getRealmRoles( token, keycloakConfig );
                }

            } else {

                realmRoles = await this.getRealmRoles( token, keycloakConfig );
            }

            let rolesArr = realmRoles.filter( role => roles.includes( role.name ) );

            let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users/${userId}/role-mappings/realm`;


            let config = {

                method: method,
                url: URL,
                headers: {
                    Authorization: `Bearer ${token}`,
                },
                data: rolesArr,
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, false );
                resolve( tokenResponse.data );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "User Roles Modification Error: An error occurred while adding or removing roles of the user using the user id.",
                    error_detail: error
                } );
            }
        } );
    }

    async addOrRemoveUserGroup( userId, groups, operation, adminToken, keycloakConfig ) {


        return new Promise( async ( resolve, reject ) => {

            let method = ( operation == 'remove' ) ? 'delete' : 'put';

            let config = {
                method: method,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`,
                }
            };

            for ( let group of groups ) {

                let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users/${userId}/groups/${group}`;
                config.url = URL;

                if ( method == 'put' ) {

                    config.data = {
                        realm: keycloakConfig[ "realm" ],
                        userId: userId,
                        groupId: group.id
                    }
                }

                try {

                    let tokenResponse = await requestController.httpRequest( config, false );

                } catch ( err ) {

                    let error = await errorService.handleError( err );

                    reject( {

                        error_message: "User Groups Modification Error: An error occurred while adding or removing group of the user using the user id.",
                        error_detail: error
                    } );

                }

            }

            resolve( [] );

        } );

    }

    async getKeycloakUserGroups( userId, adminToken, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users/${userId}/groups/`;

            let config = {
                method: "get",
                url: URL,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`,
                }
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, false );
                resolve( tokenResponse.data );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "User Groups Fetch Error: An error occurred while fetching the groups of the user using the user id.",
                    error_detail: error
                } );
            }
        } );

    }

    async gettingGroupByGroupName( groupNames, adminToken, keycloakConfig ) {

        return new Promise( async ( resolve, reject ) => {

            let groups = [];

            try {

                for ( let name of groupNames ) {

                    let URL = `${keycloakConfig[ "auth-server-url" ]}admin/realms/${keycloakConfig[ "realm" ]}/groups?search=${name}&exact=true`;

                    let config = {
                        method: "get",
                        url: URL,
                        headers: {
                            "Content-Type": "application/json",
                            Authorization: `Bearer ${adminToken}`,
                        }
                    };

                    let tokenResponse = await requestController.httpRequest( config, false );

                    if ( tokenResponse.data.length > 0 ) {

                        let groupData = tokenResponse.data.filter( group => group.name == name );

                        if ( groupData.length > 0 ) {

                            groups.push( {
                                id: tokenResponse.data[ 0 ].id,
                                name: tokenResponse.data[ 0 ].name
                            } );
                        }

                    }
                }

                resolve( groups );

            } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                    error_message: "Groups by Name Fetch Error: An error occurred while fetching groups using the group name.",
                    error_detail: error
                } );
            }



        } );

    }

    // ===================== Team Members Sync Helper Functions ===============
    addOrRemoveAgentsOrSupervisors( ciscoUsers, cxTeamsMembers, keycloakUsers ) {

        // Arrays to hold the results
        const agentsToAdd = {};
        const agentsToRemove = {};
        const supervisorsToAdd = { primary: {}, secondary: {} };
        const supervisorsToRemove = { primary: {}, secondary: {} };

        // To track users already marked for removal
        const usersAlreadyMarkedForRemoval = new Set();

        // Check agents
        for ( let user of ciscoUsers ) {

            const cxTeam = this.getCxTeamByName( user?.team?.name, cxTeamsMembers );

            if ( cxTeam ) {

                const cxAgent = cxTeam?.agents?.find(
                    ( agent ) => agent?.user?.username === ( user?.username ).toLowerCase()
                );

                // If the agent is not already part of the right team, add them
                if ( !cxAgent ) {
                    if ( !agentsToAdd[ cxTeam?.teamId ] ) {
                        agentsToAdd[ cxTeam?.teamId ] = [];
                    }
                    agentsToAdd[ cxTeam?.teamId ].push( user );
                }

                // Remove the agent if they are part of the wrong team
                cxTeamsMembers.forEach( ( team ) => {

                    if ( team?.teamName !== user?.team?.name ) {

                        const agentInWrongTeam = team?.agents?.find(
                            ( agent ) => agent.user.username === ( user.username ).toLowerCase()
                        );

                        if ( agentInWrongTeam ) {

                            if ( !agentsToRemove[ team.teamId ] ) {
                                agentsToRemove[ team.teamId ] = [];
                            }
                            agentsToRemove[ team.teamId ].push( user );
                        }
                    }
                } );
            }
        }

        // Check supervisors
        for ( let user of ciscoUsers ) {

            user?.supervisedTeams?.forEach( ( supervisedTeam ) => {

                const cxTeam = this.getCxTeamByName( supervisedTeam?.name, cxTeamsMembers );

                if ( cxTeam ) {

                    const cxSupervisor = cxTeam?.supervisors?.find(
                        ( supervisor ) => supervisor?.user?.username === ( user?.username ).toLowerCase()
                    );

                    // Add supervisor to correct team if not already there
                    if ( !cxSupervisor ) {

                        // Check if there's already a primary supervisor, if not add this user as primary
                        const primarySupervisor = cxTeam.supervisors?.find(
                            ( supervisor ) => supervisor?.user && supervisor.type === 'primary-supervisor'
                        );

                        let supervisorType = ( primarySupervisor || supervisorsToAdd.primary.hasOwnProperty( supervisedTeam?.id ) ) ? 'secondary' : 'primary';

                        if ( !supervisorsToAdd[ supervisorType ][ supervisedTeam.id ] ) {

                            supervisorsToAdd[ supervisorType ][ supervisedTeam.id ] = [];
                        }

                        let cxUser = keycloakUsers.find( keycloakUser => keycloakUser.username === ( user?.username ).toLowerCase() );
                        cxUser.ciscoTeam = supervisedTeam.name;

                        supervisorsToAdd[ supervisorType ][ supervisedTeam.id ].push( cxUser );
                    }
                }
            } );


            // For each CX Team, check if user is a supervisor
            cxTeamsMembers.forEach( ( cxTeam ) => {

                // Check if the user is a supervisor in the CX Team
                const cxSupervisor = cxTeam?.supervisors?.find(
                    ( supervisor ) => supervisor?.user?.username === ( user?.username ).toLowerCase()
                );

                // If the user is a supervisor in a team they shouldn't be managing, remove them
                if ( cxSupervisor && !user?.supervisedTeams?.some( ( supervisedTeam ) => supervisedTeam.name === cxTeam.teamName ) ) {

                    // Determine if the supervisor is primary or secondary
                    const supervisorType = cxSupervisor.type === 'primary-supervisor' ? 'primary' : 'secondary';

                    if ( !supervisorsToRemove[ supervisorType ][ cxTeam.teamId ] ) {

                        supervisorsToRemove[ supervisorType ][ cxTeam.teamId ] = [];
                    }

                    let cxUser = keycloakUsers.find( keycloakUser => keycloakUser.username === ( user?.username ).toLowerCase() );
                    supervisorsToRemove[ supervisorType ][ cxTeam.teamId ].push( cxUser );
                }
            } );
        }

        // Output the results

        return {
            agentsToAdd: agentsToAdd,
            agentsToRemove: agentsToRemove,
            supervisorsToAdd: supervisorsToAdd,
            supervisorsToRemove: supervisorsToRemove
        }

    }

    async addAgentsToTeams( cxURL, agentsToAdd ) {

        return new Promise( async ( resolve, reject ) => {


            for ( let teamId in agentsToAdd ) {

                if ( agentsToAdd.hasOwnProperty( teamId ) ) {


                    // Extract usernames and convert them to lowercase
                    const usernames = agentsToAdd[ teamId ].map( item => ( item.username ).toLowerCase() );

                    // Prepare the data object for the API request
                    const requestData = {
                        type: "agent",
                        usernames: usernames
                    };

                    // Set the URL for the API request
                    const URL = cxURL + `team/${teamId}/member`;

                    // Set up the configuration for the API request
                    let config = {
                        method: 'post',
                        url: URL,
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        data: requestData
                    };

                    try {

                        await requestController.httpRequest( config, false );

                    }
                    catch ( er ) {

                        console.log( er.response );
                        reject( er.status );
                    }
                }
            }

            resolve( 'Agents Added...' );
        } )
    }

    async removeAgentsFromTeams( cxURL, agentsToRemove ) {

        return new Promise( async ( resolve, reject ) => {


            for ( let teamId in agentsToRemove ) {

                if ( agentsToRemove.hasOwnProperty( teamId ) ) {


                    // Extract usernames and convert them to lowercase
                    let usernames = agentsToRemove[ teamId ].map( item => ( item.username ).toLowerCase() );
                    usernames = usernames.join( ',' );

                    // Set the URL for the API request
                    const URL = cxURL + `team/${teamId}/member?type=agent&usernames=${usernames}`;

                    // Set up the configuration for the API request
                    let config = {
                        method: 'delete',
                        url: URL
                    };

                    try {

                        await requestController.httpRequest( config, false );

                    }
                    catch ( er ) {

                        console.log( er.response );
                        reject( er.status );
                    }
                }
            }

            resolve( 'Agents Removed...' );
        } )
    }

    async addPrimarySupervisorsToTeams( cxURL, primarySupervisorsToAdd ) {

        return new Promise( async ( resolve, reject ) => {

            for ( let teamId in primarySupervisorsToAdd ) {

                if ( primarySupervisorsToAdd.hasOwnProperty( teamId ) ) {

                    // Extract usernames and convert them to lowercase
                    const userId = primarySupervisorsToAdd[ teamId ].map( item => item.id );

                    // Prepare the data object for the API request
                    const requestData = {

                        supervisor_Id: userId[ 0 ]
                    };

                    // Set the URL for the API request
                    const URL = cxURL + `team/${teamId}/supervisor`;

                    // Set up the configuration for the API request
                    let config = {
                        method: 'put',
                        url: URL,
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        data: requestData
                    };

                    try {

                        await requestController.httpRequest( config, false );

                    }
                    catch ( er ) {

                        console.log( er.response );
                        reject( er.status );
                    }
                }
            }

            resolve( 'Secondary Supervisors Added...' );
        } )
    }

    async addSecondarySupervisorsToTeams( cxURL, secondarySupervisorsToAdd ) {

        return new Promise( async ( resolve, reject ) => {


            for ( let teamId in secondarySupervisorsToAdd ) {

                if ( secondarySupervisorsToAdd.hasOwnProperty( teamId ) ) {


                    // Extract usernames and convert them to lowercase
                    const usernames = secondarySupervisorsToAdd[ teamId ].map( item => ( item.username ).toLowerCase() );

                    // Prepare the data object for the API request
                    const requestData = {
                        type: "secondary-supervisor",
                        usernames: usernames
                    };

                    // Set the URL for the API request
                    const URL = cxURL + `team/${teamId}/member`;

                    // Set up the configuration for the API request
                    let config = {
                        method: 'post',
                        url: URL,
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        data: requestData
                    };

                    try {

                        await requestController.httpRequest( config, false );

                    }
                    catch ( er ) {

                        console.log( er.response );
                        reject( er.status );
                    }
                }
            }

            resolve( 'Secondary Supervisors Added...' );
        } )
    }

    async removePrimarySupervisorsFromTeams( cxURL, primarySupervisorsToRemove ) {

        return new Promise( async ( resolve, reject ) => {


            for ( let teamId in primarySupervisorsToRemove ) {


                // Set the URL for the API request
                const URL = cxURL + `team/${teamId}/supervisor`;

                // Set up the configuration for the API request
                let config = {
                    method: 'delete',
                    url: URL
                };

                try {

                    await requestController.httpRequest( config, false );

                }
                catch ( er ) {

                    console.log( er.response );
                    reject( er.status );
                }

            }

            resolve( 'Primary Supervisors Removed...' );
        } )
    }

    async removeSecondarySupervisorsFromTeams( cxURL, secondarySupervisorsToRemove ) {

        return new Promise( async ( resolve, reject ) => {


            for ( let teamId in secondarySupervisorsToRemove ) {

                if ( secondarySupervisorsToRemove.hasOwnProperty( teamId ) ) {


                    // Extract usernames and convert them to lowercase
                    let usernames = secondarySupervisorsToRemove[ teamId ].map( item => ( item.username ).toLowerCase() );
                    usernames = usernames.join( ',' );

                    // Set the URL for the API request
                    const URL = cxURL + `team/${teamId}/member?type=secondary-supervisor&usernames=${usernames}`;

                    // Set up the configuration for the API request
                    let config = {
                        method: 'delete',
                        url: URL
                    };

                    try {

                        await requestController.httpRequest( config, false );

                    }
                    catch ( er ) {

                        console.log( er.response );
                        reject( er.status );
                    }
                }
            }

            resolve( 'Secondary Supervisors Added...' );
        } )
    }

    mapTeamMembersToKeycloak( CiscoTeams, CXTeamMembers, UniqueKeycloakMembers ) {
        // Initialize an object to store the result
        let cxAgents = {};
        let cxSupervisors = { primary: {}, secondary: {} };

        // Loop through each Cisco team
        CiscoTeams.forEach( ciscoTeam => {
            const ciscoTeamId = ciscoTeam.id;

            // Find the corresponding CX Team for this Cisco Team
            const cxTeam = CXTeamMembers.find( team => team.teamId === ciscoTeamId );

            if ( cxTeam ) {

                // Check agents
                cxTeam?.agents?.forEach( agent => {
                    // Find the corresponding Keycloak user based on the agent's username
                    const keycloakAgent = UniqueKeycloakMembers.find( user => user?.username === agent?.user?.username );
                    if ( keycloakAgent ) {

                        if ( !cxAgents[ ciscoTeamId ] ) {
                            cxAgents[ ciscoTeamId ] = []
                        }

                        cxAgents[ ciscoTeamId ].push( {
                            id: keycloakSupervisor?.id,
                            username: keycloakSupervisor?.username
                        } );
                    }
                } );

                // Check supervisors
                cxTeam?.supervisors?.forEach( supervisor => {
                    // Find the corresponding Keycloak user based on the supervisor's username
                    const keycloakSupervisor = UniqueKeycloakMembers.find( user => user?.username === supervisor?.user?.username );

                    if ( keycloakSupervisor ) {

                        // Determine if the supervisor is primary or secondary
                        const supervisorType = supervisor?.type === 'primary-supervisor' ? 'primary' : 'secondary';

                        if ( !cxSupervisors[ supervisorType ][ ciscoTeamId ] ) {

                            cxSupervisors[ supervisorType ][ ciscoTeamId ] = [];
                        }

                        cxSupervisors[ supervisorType ][ ciscoTeamId ].push( {
                            id: keycloakSupervisor?.id,
                            username: keycloakSupervisor?.username
                        } );
                    }
                } );
            }
        } );

        return {
            cxAgents: cxAgents,
            cxSupervisors: cxSupervisors
        };
    }


    // Helper function to get the CX Team by teamName
    getCxTeamByName( teamName, cxTeamsMembers ) {

        return cxTeamsMembers.find( ( team ) => team.teamName === teamName );
    }

    async maskCredentials( username, password ) {

        let token = Buffer.from( `${username}:${password}`, 'utf8' ).toString( 'base64' );
        return token;

    }

}

function checkForMissingRole( keycloakRealmRoles, requiredRoles ) {

    // Convert the object names to a Set for faster lookup
    const rolesNamesSet = new Set( keycloakRealmRoles.map( role => role.name ) );

    // Use the some method to check if at least one role is missing
    const isMissing = requiredRoles.some( role => !rolesNamesSet.has( role ) );

    return !isMissing;
}

module.exports = CiscoSyncService;


