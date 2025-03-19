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
        const disablePromises = usersToDisable.map( user => this.updateKeycloakUser( [], user, keycloakConfig, adminToken ) );
        await Promise.all( disablePromises );

        // Step 5: Process Cisco users (create or update)
        const updatePromises = ciscoUsers.map( async ( ciscoUser ) => {

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
        } );

        // Wait for all the update operations to complete
        await Promise.all( updatePromises );
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

    // ===================== Assign Users to Teams =====================
    async assignUsersToTeams( ciscoUsers, ciscoTeams ) {
        const cxTeams = await this.fetchCXTeams();
        const cxUsers = await this.fetchCXUsers();

        // Create maps for fast lookup
        const cxTeamMap = new Map();
        const cxUserMap = new Map();

        cxTeams.forEach( ( team ) => {
            if ( team.source === 'CISCO' ) {
                cxTeamMap.set( team.team_name, team.id ); // Map team name to ID
            }
        } );

        cxUsers.forEach( ( user ) => {
            if ( user.source === 'CISCO' ) {
                cxUserMap.set( user.user_name, user.id ); // Map user name to ID
            }
        } );

        // Assign users to their respective teams in CX
        for ( let ciscoUser of ciscoUsers ) {
            const cxUserId = cxUserMap.get( ciscoUser.name );

            if ( cxUserId ) {
                for ( let ciscoTeamName of ciscoUser.teams ) {
                    const cxTeamId = cxTeamMap.get( ciscoTeamName );

                    if ( cxTeamId ) {
                        try {
                            const data = { user_id: cxUserId, team_id: cxTeamId };
                            await axios.post( `${this.cxBaseUrl}/user-team`, data );
                            console.log( `Assigned user ${ciscoUser.name} to team ${ciscoTeamName}` );
                        } catch ( error ) {
                            console.error( 'Error assigning user to team:', error );
                        }
                    }
                }
            }
        }
    }

    // ===================== Main Function to Sync Everything =====================
    async syncCiscoData( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL, keycloakConfig, adminToken ) {

        try {

            let ciscoUsers = [];
            // Step 1: Fetch the Cisco and CX data for users and teams

            //Fetch Cisco Teams
            const ciscoTeams = await this.fetchCiscoTeams( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL );

            //Fetch Cisco Users
            ciscoUsers = await this.fetchCiscoUsers( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL );

            //Fetch CX Team
            const cxTeams = await this.fetchCXTeams( keycloakConfig[ "ef-server-url" ] );
            //console.log( cxTeams );

            /*
            console.log( "======= Cisco Teams ======" );
            console.log( ciscoTeams ); 
            console.log( "======= Cisco Users ======" );

            ciscoUsers.map( user => {
                console.log( user.supervisedTeams );
            } );

            console.log( "======= CX Teams ======" );
            console.log( cxTeams );
            */

            let ciscoTeamsIds = ciscoTeams.map( team => Number( team.id ) );
            const cxTeamsMembers = await this.fetchCXTeamsMembers( keycloakConfig[ "ef-server-url" ], ciscoTeamsIds );

            //filtration start

            // Helper function to get the CX Team by teamName
            function getCxTeamByName( teamName ) {

                return cxTeamsMembers.find( ( team ) => team.teamName === teamName );
            }

            // Arrays to hold the results
            const agentsToAdd = {};
            const agentsToRemove = {};
            const supervisorsToAdd = {};
            const supervisorsToRemove = {};

            // Check agents
            ciscoUsers.forEach( ( user ) => {

                const cxTeam = getCxTeamByName( user.team.name );

                if ( cxTeam ) {

                    const cxAgent = cxTeam?.agents?.find(
                        ( agent ) => agent.user.username === ( user.username ).toLowerCase()
                    );

                    // If the agent is not already part of the right team, add them
                    if ( !cxAgent ) {
                        if ( !agentsToAdd[ cxTeam.teamName ] ) {
                            agentsToAdd[ cxTeam.teamName ] = [];
                        }
                        agentsToAdd[ cxTeam.teamName ].push( user );
                    }

                    // Remove the agent if they are part of the wrong team
                    cxTeamsMembers.forEach( ( team ) => {

                        if ( team.teamName !== user.team.name ) {


                            const agentInWrongTeam = team?.agents?.find(
                                ( agent ) => agent.user.username === ( user.username ).toLowerCase()
                            );

                            if ( agentInWrongTeam ) {

                                if ( !agentsToRemove[ team.teamName ] ) {
                                    agentsToRemove[ team.teamName ] = [];
                                }
                                agentsToRemove[ team.teamName ].push( user );
                            }
                        }
                    } );
                }
            } );

            // Check supervisors
            ciscoUsers.forEach( ( user ) => {

                user?.supervisedTeams?.forEach( ( supervisedTeam ) => {

                    const cxTeam = getCxTeamByName( supervisedTeam?.name );

                    if ( cxTeam ) {
                        const cxSupervisor = cxTeam?.supervisors?.find(
                            ( supervisor ) => supervisor?.user?.username === ( user?.username ).toLowerCase()
                        );

                        // Add supervisor to correct team if not already there
                        if ( !cxSupervisor ) {
                            if ( !supervisorsToAdd[ supervisedTeam.name ] ) {
                                supervisorsToAdd[ supervisedTeam.name ] = [];
                            }
                            supervisorsToAdd[ supervisedTeam.name ].push( user );
                        }
                    }
                } );

                // For each CX Team
                cxTeamsMembers.forEach( ( cxTeam ) => {

                    // Check if the user is a supervisor in the CX Team
                    const cxSupervisor = cxTeam?.supervisors?.find(
                        ( supervisor ) => supervisor?.user?.username === ( user?.username ).toLowerCase()
                    );

                    // If the user is a supervisor in a team they shouldn't be managing, remove them
                    if ( cxSupervisor && !user?.supervisedTeams?.some( supervisedTeam => supervisedTeam.name === cxTeam.teamName ) ) {
                        // If the user is not supposed to supervise this team, add them to supervisorsToRemove
                        if ( !supervisorsToRemove[ cxTeam.teamName ] ) {
                            supervisorsToRemove[ cxTeam.teamName ] = [];
                        }
                        supervisorsToRemove[ cxTeam.teamName ].push( user );
                    }

                } );
            } );

            // Output the results
            console.log( 'Agents to Add:', agentsToAdd );
            console.log( 'Agents to Remove:', agentsToRemove );
            console.log( 'Supervisors to Add:', supervisorsToAdd );
            console.log( 'Supervisors to Remove:', supervisorsToRemove );



            //filtration end




            // Fetch Keycloak users
            const keycloakUsers = await this.fetchKeycloakUsers( keycloakConfig[ "auth-server-url" ], adminToken );
            const keycloakUsersByRole = await this.fetchKeycloakUsersByRole( keycloakConfig[ "auth-server-url" ], adminToken );
            const keycloakUsersByPermissionGroups = await this.fetchKeycloakUsersByPermissionGroups( keycloakConfig, adminToken );

            ciscoUsers = ciscoUsers.slice( 0, 2 );

            // Step 2: Sync Teams to CX
            await this.syncTeamsToCX( ciscoTeams, cxTeams, keycloakConfig[ "ef-server-url" ] );

            // Step 3: Sync Users to CX (only after teams are synced)
            //await this.syncUsersToCX( ciscoUsers, keycloakUsers, keycloakUsersByRole, keycloakUsersByPermissionGroups, keycloakConfig, adminToken );

            // Step 4: Assign Users to Teams
            //await this.assignUsersToTeams( ciscoUsers, ciscoTeams );

            console.log( 'Data synchronization complete!' );
        } catch ( error ) {

            console.error( 'Error in Cisco data synchronization:', error );
        }
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
            console.log( teamIdsArr );
            let URL = `${cxURL}team/member?teamIds=${teamIdsArr}`;

            let config = {
                method: 'get',
                url: URL
            };

            try {

                let tokenResponse = await requestController.httpRequest( config, true );

                // Filter the teams to only include those with source: "CISCO"
                //let filteredTeams = tokenResponse.data.filter( team => team.source === 'CISCO' );

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


