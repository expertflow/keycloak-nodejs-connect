var session = require("express-session");
var Keycloak = require("keycloak-connect");
const Joi = require('joi');
const parseXMLString = require('xml2js').parseString;
var requestController = require("../controller/requestController.js");
var memory = new session.MemoryStore();
var keycloakConfig = null;

const FinesseService = require('./finesseService');
const TeamsService = require('./teamsService');

const finesseService = new FinesseService();
const teamsService = new TeamsService();

class KeycloakService extends Keycloak {

    constructor(config) {

        keycloakConfig = { ...config };
        super({ store: memory }, keycloakConfig);   //initialising keycloak-connect   //Keycloak = new Keycloak({store: memory}, config);
        // this.keycloakConfig = config;
    }

    //Based on the attributes it either authenticate keycloak user or finesse user.
    async authenticateUserViaKeycloak(user_name, user_password, realm_name, finesseUrl, userRoles, finesseToken) {

        let token = '';

        // If finesseUrl is empty it means normal keycloak auth is required.
        if (finesseUrl == '') {

            token = await this.getKeycloakTokenWithIntrospect(user_name, user_password, realm_name);
            return token;

        } else {

            // Finesse Auth, takes userRole in argument to create user along with role.
            token = await this.authenticateFinesse(user_name, user_password, finesseUrl, userRoles, finesseToken)
            return token;

        }

    }

    getAccessToken(user_name, user_password) {

        return new Promise(async (resolve, reject) => {

            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig["realm"] + '/protocol/openid-connect/token';

            //keycloakConfig["auth-server-url"] +'realms
            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    username: user_name,
                    password: user_password,
                    client_id: keycloakConfig.CLIENT_ID,
                    client_secret: keycloakConfig.credentials.secret,
                    grant_type: keycloakConfig.GRANT_TYPE,
                },
            };

            try {
                let tokenResponse = await requestController.httpRequest(config, true);
                resolve(tokenResponse.data);
            }
            catch (er) {
                reject(er);
            }

        });
    }

    // this function requires an Admin user in keycloak.json having realm-management roles
    async getKeycloakTokenWithIntrospect(user_name, user_password, realm_name) {

        return new Promise(async (resolve, reject) => {
            let token;
            let refresh_token;
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + realm_name + '/protocol/openid-connect/token'
            //keycloakConfig["auth-server-url"] +'realms
            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    username: user_name,
                    password: user_password,
                    client_id: keycloakConfig.CLIENT_ID,
                    client_secret: keycloakConfig.credentials.secret,
                    grant_type: keycloakConfig.GRANT_TYPE,
                },
            };

            try {
                //  T.O.K.E.N   R.E.Q.U.E.S.T   # 1   ( P.E.R.M.I.S.S.I.O.N.S   N.O.T    I.N.C.L.U.D.E.D) 
                let tokenResponse = await requestController.httpRequest(config, true);

                if (tokenResponse.data.access_token) {
                    token = tokenResponse.data.access_token;
                    config.data.grant_type = 'urn:ietf:params:oauth:grant-type:uma-ticket';
                    config.data.audience = keycloakConfig.CLIENT_ID;
                    config.headers.Authorization = "Bearer " + token;
                    //  T.O.K.E.N   R.E.Q.U.E.S.T   # 2   (A.C.C.E.S.S   T.O.K.E.N   W.I.T.H   P.E.R.M.I.S.S.I.O.N.S)                 
                    try {
                        var rptResponse = await requestController.httpRequest(config, true);
                        if (rptResponse.data.access_token) {
                            token = rptResponse.data.access_token;
                            refresh_token = rptResponse.data.refresh_token;

                            var userToken = token;
                            config.data.grant_type = keycloakConfig.GRANT_TYPE;
                            config.data.token = token;
                            URL = URL + '/introspect'
                            config.url = URL;

                            //  T.O.K.E.N   R.E.Q.U.E.S.T   # 3   (A.C.C.E.S.S   T.O.K.E.N   I.N.T.R.O.S.P.E.C.T.I.O.N)
                            try {
                                let intrsopectionResponse = await requestController.httpRequest(config, true);
                                intrsopectionResponse.data.access_token = token;

                                //  T.O.K.E.N   R.E.Q.U.E.S.T   # 4   ( A.D.M.I.N.  T.O.K.E.N) 
                                try {
                                    config.data.username = keycloakConfig.USERNAME_ADMIN;
                                    config.data.password = keycloakConfig.PASSWORD_ADMIN;
                                    config.url = keycloakConfig["auth-server-url"] + 'realms/' + realm_name + '/protocol/openid-connect/token';
                                    delete config.data.audience;
                                    delete config.data.token;
                                    delete config.headers.Authorization;
                                    let adminTokenResponse = await requestController.httpRequest(config, true);
                                    if (adminTokenResponse.data.access_token) {
                                        token = adminTokenResponse.data.access_token;
                                        try {
                                            config.headers.Authorization = "Bearer " + token;
                                            config.method = 'get';
                                            config.url = keycloakConfig["auth-server-url"] + 'admin/realms/' + realm_name + '/users?username=' + user_name;
                                            delete config.data;
                                            let getuserDetails = await requestController.httpRequest(config, true);
                                            let responseObject = {
                                                'id': getuserDetails.data[0].id,
                                                'firstName': getuserDetails.data[0].firstName,
                                                'lastName': getuserDetails.data[0].lastName,
                                                'username': getuserDetails.data[0].username,
                                                'permittedResources': {
                                                    'Resources': intrsopectionResponse.data.authorization.permissions
                                                },
                                                'roles': intrsopectionResponse.data.realm_access.roles,
                                                'realm': realm_name

                                            };

                                            //Adding user custom attribute to our token object data.
                                            if (getuserDetails.data[0].attributes) {
                                                responseObject.attributes = getuserDetails.data[0].attributes;
                                            } else {
                                                responseObject.attributes = {};
                                            }

                                            delete config.headers.Authorization;
                                            delete config.data;

                                            //Fetching Groups data for each user.
                                            try {

                                                let teamData = await this.getUserSupervisedGroups(responseObject.id, responseObject.username);
                                                responseObject.userTeam = teamData.userTeam;
                                                responseObject.supervisedTeams = teamData.supervisedTeams;

                                                let finalObject = {
                                                    'token': userToken,
                                                    'refresh_token': refresh_token,
                                                    'keycloak_User': responseObject
                                                }
                                                resolve(finalObject);

                                            } catch (error) {
                                                reject("Error while fetching Groups of User in Auth Process" + error);
                                            }
                                        }
                                        catch (error) {
                                            reject("Get all users request not sent" + error);
                                        }
                                    }
                                    else {
                                        reject("Admin token Request Failed");

                                    }
                                }
                                catch (error) {
                                    reject("Admin Request not sent" + error);
                                }
                            }
                            catch (error) {
                                reject(error);
                            }
                        } else {
                            reject("RPT Request Failed");
                        }
                    } catch (error) {
                        reject(error);
                    }
                }
                else {
                    reject("Access Token Request Failed");
                }
            }
            catch (er) {
                reject(er);
            }
        });
    }

    async getUserInfoFromToken(username, token) {

        return new Promise(async (resolve, reject) => {

            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token/introspect';

            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    username: username,
                    client_id: keycloakConfig.CLIENT_ID,
                    client_secret: keycloakConfig.credentials.secret,
                    token: token
                }
            };

            try {

                let userInfo = await requestController.httpRequest(config, true);
                if (!(userInfo.data.active)) {
                    resolve({
                        'status': 401,
                        'message': 'Provided User Access Token is Expired.'
                    });
                }

                let clientRoles = userInfo.data.resource_access;
                resolve(clientRoles);

            } catch (error) {
                reject(error);
            }
        });

    }

    createResource(resource_name, resource_scope = keycloakConfig.SCOPE_NAME) {
        return new Promise(async (resolve, reject) => {

            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token'
            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: keycloakConfig.CLIENT_ID,
                    client_secret: keycloakConfig.credentials.secret,
                    grant_type: keycloakConfig.GRANT_TYPE_PAT
                },
            };
            //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1     
            try {
                let patToken = await requestController.httpRequest(config, true);
                if (patToken.data.access_token) {
                    let token = patToken.data.access_token;
                    //     C.R.E.A.T.E    R.E.S.O.U.R.C.E     R.E.Q.U.E.S.T   
                    delete config.data["client_id"];
                    delete config.data["client_secret"];
                    delete config.data["grant_type"];

                    config.data.name = resource_name;
                    config.data._id = resource_name;
                    config.data.resource_scopes = [resource_scope];

                    config.url = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/authz/protection/resource_set';
                    config.headers.Authorization = "Bearer " + token;
                    config.headers['Content-Type'] = 'application/json';

                    try {
                        let resourceResponse = await requestController.httpRequest(config, false);
                        resolve(resourceResponse);
                    } catch (error) {
                        reject(error);
                    }
                } else {
                    console.log("Token not found");
                }
            } catch (error) {
                reject(error);
            }
        });

    }

    deleteResource(resource_name) {
        return new Promise(async (resolve, reject) => {
            let token;
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token';
            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: keycloakConfig.CLIENT_ID,
                    client_secret: keycloakConfig.credentials.secret,
                    grant_type: keycloakConfig.GRANT_TYPE_PAT
                },
            };
            //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1      
            try {
                let patToken = await requestController.httpRequest(config, true);
                if (patToken.data.access_token) {
                    token = patToken.data.access_token;
                    //  D.E.L.E.T.E    R.E.S.O.U.R.C.E  A.N.D   P.E.R.M.I.S.S.I.O.N   R.E.Q.U.E.S.T   
                    let URL1 = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/authz/protection/resource_set/' + resource_name;
                    config.url = URL1;
                    config.method = 'delete';
                    config.headers.Authorization = 'Bearer ' + token;
                    delete config.data["grant_type"];
                    config.data.name = resource_name;
                    try {
                        let resourceResponse = await requestController.httpRequest(config, true);
                        //         // WE NEED admin token to delete policy
                        //         /// admin token request
                        config.method = 'post';
                        config.url = URL;
                        delete config.headers["Authorization"];
                        config.data.client_id = keycloakConfig.CLIENT_ID;
                        config.data.username = keycloakConfig.USERNAME_ADMIN;
                        config.data.password = keycloakConfig.PASSWORD_ADMIN;
                        config.data.grant_type = keycloakConfig.GRANT_TYPE;
                        config.data.client_secret = keycloakConfig.credentials.secret;
                        try {
                            let adminTokenResponse = await requestController.httpRequest(config, true);
                            token = adminTokenResponse.data.access_token;
                            // now deleting policy
                            config.method = 'delete';
                            delete config.data;
                            let URL6 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/clients/' + keycloakConfig.CLIENT_DB_ID + '/authz/resource-server/policy/user/' + resource_name + '-policy';
                            config.url = URL6;
                            delete config.headers['Accept'];
                            delete config.headers['cache-control'];
                            delete config.headers['Content-Type'];
                            config.headers.Authorization = 'Bearer ' + token;
                            try {
                                let deletePolicy = await requestController.httpRequest(config, false);
                                resolve(deletePolicy);
                            } catch (error) {
                                reject(error);
                            }
                        } catch (error) {
                            reject(error);
                        }
                    } catch (error) {
                        reject(error);
                    }
                }
            } catch (error) {
                reject(error);
            }
        });
    }

    createPolicy(policyName, roles) {

        return new Promise(async (resolve, reject) => {
            let token;
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token'
            var config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: keycloakConfig.CLIENT_ID,
                    username: keycloakConfig.USERNAME_ADMIN,
                    password: keycloakConfig.PASSWORD_ADMIN,
                    grant_type: keycloakConfig.GRANT_TYPE,
                    client_secret: keycloakConfig.credentials.secret
                }
            };
            try {

                let adminTokenResponse = await requestController.httpRequest(config, true);
                token = adminTokenResponse.data.access_token;

                //   T.O.K.E.N    R.E.Q.U.E.S.T  (user with admin is already defined in keycloak with roles 'realm-management')
                //   //  C.R.E.A.T.E    U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y  
                let URL3 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/clients/' + keycloakConfig.CLIENT_DB_ID + '/authz/resource-server/policy/role';
                config.url = URL3;
                config.headers['Content-Type'] = 'application/json';
                config.headers.Authorization = 'Bearer ' + token;

                config.data.decisionStrategy = 'AFFIRMATIVE';
                config.data.logic = "POSITIVE";
                config.data.name = policyName;
                config.data.type = "role";
                config.data.id = policyName;
                config.data.roles = roles;

                delete config.data["client_id"];
                delete config.data["client_secret"];
                delete config.data["grant_type"];
                delete config.data["username"];
                delete config.data["password"];
                config.data = JSON.stringify(config.data);

                try {
                    let policyResponse = await requestController.httpRequest(config, false);
                    resolve(policyResponse);
                } catch (error) {
                    reject("Policy error" + error);
                }

            } catch (error) {
                reject(error);
            }

        });

    }

    createPermission(resourceName, policyName, permissionName, scopeName) {

        return new Promise(async (resolve, reject) => {
            let token;
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token'
            var config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: keycloakConfig.CLIENT_ID,
                    username: keycloakConfig.USERNAME_ADMIN,
                    password: keycloakConfig.PASSWORD_ADMIN,
                    grant_type: keycloakConfig.GRANT_TYPE,
                    client_secret: keycloakConfig.credentials.secret
                }
            };

            try {
                let adminTokenResponse = await requestController.httpRequest(config, true);
                token = adminTokenResponse.data.access_token;
                //   T.O.K.E.N    R.E.Q.U.E.S.T  (user with admin is already defined in keycloak with roles 'realm-management')
                //   //  C.R.E.A.T.E    U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y  
                let URL3 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/clients/' + keycloakConfig.CLIENT_DB_ID + '/authz/resource-server/permission/scope';
                config.url = URL3;
                config.headers['Content-Type'] = 'application/json';
                config.headers.Authorization = 'Bearer ' + token;

                config.data.decisionStrategy = 'AFFIRMATIVE';
                config.data.logic = "POSITIVE";
                config.data.name = permissionName;
                config.data.policies = policyName;
                config.data.resources = resourceName;
                config.data.scopes = scopeName;
                config.data.type = "scope";
                config.data.id = permissionName;


                delete config.data["client_id"];
                delete config.data["client_secret"];
                delete config.data["grant_type"];
                delete config.data["username"];
                delete config.data["password"];
                config.data = JSON.stringify(config.data);

                try {
                    let policyResponse = await requestController.httpRequest(config, false);
                    resolve(policyResponse);
                } catch (error) {
                    reject("Policy error" + error);
                }

            } catch (error) {
                reject(error);
            }

        });

    }

    //   R.E.S.O.U.R.C.E    A.U.T.H.O.R.I.Z.A.T.I.O.N        (    E.V.A.L.U.A.T.E    U.S.E.R    T.O   A    R.E.S.O.U.R.C.E   )
    resourceAuthorization(keycloak_user_id, resource_name) {
        return new Promise(async (resolve, reject) => {
            let token;
            var config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: keycloakConfig.CLIENT_ID,
                    username: keycloakConfig.USERNAME_ADMIN,
                    password: keycloakConfig.PASSWORD_ADMIN,
                    grant_type: keycloakConfig.GRANT_TYPE,
                    client_secret: keycloakConfig.credentials.secret
                }
            };
            try {
                let adminTokenResponse = await requestController.httpRequest(config, true);
                token = adminTokenResponse.data.access_token;
                // EVALUATION REQUEST
                var data = JSON.stringify({
                    "resources": [{ "_id": resource_name }],
                    "clientId": keycloakConfig.CLIENT_DB_ID,
                    "userId": keycloak_user_id
                });
                config.data.clientId = keycloakConfig.CLIENT_DB_ID;
                config.data.resources = [{ "_id": resource_name }];
                config.data.userId = keycloak_user_id;
                delete config.data["username"];
                delete config.data["password"];
                delete config.data["grant_type"];
                delete config.data["client_secret"];
                delete config.data["client_id"];
                let URL5 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/clients/' + keycloakConfig.CLIENT_DB_ID + '/authz/resource-server/policy/evaluate';
                config.url = URL5;
                config.headers['Content-Type'] = 'application/json';
                config.headers.Authorization = 'Bearer ' + token,
                    config.data = JSON.stringify(config.data);

                try {
                    let evaluationResponse = await requestController.httpRequest(config, false);
                    resolve(evaluationResponse);
                }
                catch (error) {
                    reject(error);
                };
            } catch (error) {
                reject(error);
            };
        });
    }

    revokeUseronResource(resource_name, keycloak_user_id) {
        return new Promise(async (resolve, reject) => {
            let token;
            try {
                // let checkAccess=  await ResourceAuthorization(keycloak_user_id,resource_name).then((e)=>{
                //     if(e.toString()==='PERMIT'){
                // WE NEED admin token
                /// admin token request

                var config = {
                    method: 'post',
                    url: URL,
                    headers: {
                        'Accept': 'application/json',
                        'cache-control': 'no-cache',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    data: {
                        client_id: keycloakConfig.CLIENT_ID,
                        username: keycloakConfig.USERNAME_ADMIN,
                        password: keycloakConfig.PASSWORD_ADMIN,
                        grant_type: keycloakConfig.GRANT_TYPE,
                        client_secret: keycloakConfig.credentials.secret
                    }
                };
                try {
                    let adminTokenResponse = await requestController.httpRequest(config, true);
                    token = adminTokenResponse.data.access_token;
                    // now deleting policy
                    config.method = 'delete';
                    delete config.data;
                    let URL6 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/clients/' + keycloakConfig.CLIENT_DB_ID + '/authz/resource-server/policy/user/' + resource_name + '-policy';
                    config.url = URL6;
                    delete config.headers['Accept'];
                    delete config.headers['cache-control'];
                    delete config.headers['Content-Type'];
                    config.headers.Authorization = 'Bearer ' + token;
                    try {
                        let deletePolicy = await requestController.httpRequest(config, false);
                        resolve(deletePolicy);
                    } catch (error) {
                        reject(error);
                    }
                } catch (error) {
                    reject(error);
                }
                // }else{
                //     console.log("user already not permitted");
                // }
            } catch (er) {
                reject("Policy error" + error);
            };
        });
    }

    //function to be used only in teams implementation
    async getUserSupervisedGroups(userId, username) {

        return new Promise(async (resolve, reject) => {

            let error;
            let token;
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token';

            try {

                var config = {
                    method: 'post',
                    url: URL,
                    headers: {
                        'Accept': 'application/json',
                        'cache-control': 'no-cache',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    data: {
                        client_id: keycloakConfig.CLIENT_ID,
                        username: keycloakConfig.USERNAME_ADMIN,
                        password: keycloakConfig.PASSWORD_ADMIN,
                        grant_type: keycloakConfig.GRANT_TYPE,
                        client_secret: keycloakConfig.credentials.secret
                    }
                };

                try {

                    let adminTokenResponse = await requestController.httpRequest(config, true);
                    token = adminTokenResponse.data.access_token;

                    config.method = 'get';
                    delete config.data;
                    delete config.url;

                    let URL2 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/users/' + userId + '/groups';
                    config.url = URL2;
                    config.headers.Authorization = 'Bearer ' + token;

                    try {

                        let userGroup = await requestController.httpRequest(config, true);
                        let team = {};

                        if (userGroup.data.length != 0) {


                            let groups = userGroup.data;
                            let userTeam = {};
                            let supervisedTeams = [];

                            let filteredTeams = groups.filter(group => !group.name.includes('_permission'));


                            userTeam = {
                                'teamId': filteredTeams[0].id,
                                'teamName': filteredTeams[0].name
                            }

                            team.userTeam = userTeam;

                            config.method = 'get';
                            delete config.data;
                            delete config.url;

                            let URL3 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/groups';
                            config.url = URL3;
                            config.headers.Authorization = 'Bearer ' + token;

                            try {

                                let allGroups = await requestController.httpRequest(config, true);

                                for (let group of allGroups.data) {

                                    let result = await teamsService.getGroupByGroupID(group.id, username, token, keycloakConfig);

                                    if (result && !result.teamName.includes('_permission')) {
                                        supervisedTeams.push(result);
                                    }
                                };

                                team.supervisedTeams = supervisedTeams;
                                resolve(team);

                            } catch (er) {

                                error = await this.checkErrorType(er);
                                reject(error);
                            }
                        } else {

                            team.userTeam = {};
                            team.supervisedTeams = [];

                            resolve(team);
                        }

                    } catch (er) {

                        error = await this.checkErrorType(er);
                        reject(error);
                    }
                } catch (er) {

                    error = await this.checkErrorType(er);
                    reject(error);
                }
            } catch (er) {

                error = await this.checkErrorType(er);
                reject(error);
            };
        });

    }

    //function to be used only in teams implementation
    async getTeamUsers(keycloakObj, groupsIdsArr, userToken) {

        return new Promise(async (resolve, reject) => {

            let token;
            let message;
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token';

            try {

                if (typeof keycloakObj == 'object' && Object.keys(keycloakObj).length != 0
                    && Array.isArray(groupsIdsArr) && userToken.length > 0) {

                    //Validate whether user in keycloakObj is same as user in userToken.
                    const parseJwt = (userToken) => {
                        try {
                            return JSON.parse(Buffer.from(userToken.split('.')[1], 'base64').toString());
                        } catch (er) {
                            return null;
                        }
                    };

                    let verifyToken = parseJwt(userToken);

                    if (keycloakObj.username != verifyToken.preferred_username) {

                        message = `The data provided in Keycloak Object as an Argument doesn't belong to current Logged-In user.`;

                        resolve({
                            "status": 401,
                            "message": message
                        });
                    }

                    var config = {
                        method: 'post',
                        url: URL,
                        headers: {
                            'Accept': 'application/json',
                            'cache-control': 'no-cache',
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        data: {
                            client_id: keycloakConfig.CLIENT_ID,
                            username: keycloakConfig.USERNAME_ADMIN,
                            password: keycloakConfig.PASSWORD_ADMIN,
                            grant_type: keycloakConfig.GRANT_TYPE,
                            client_secret: keycloakConfig.credentials.secret
                        }
                    };


                    try {


                        let adminTokenResponse = await requestController.httpRequest(config, true);
                        token = adminTokenResponse.data.access_token;
                        let allUsers = [];
                        let groupsData;

                        config.method = 'get';
                        delete config.data;
                        delete config.url;
                        config.headers.Authorization = 'Bearer ' + token;
                        let clientRoles = await this.getUserInfoFromToken(keycloakObj.username, userToken);

                        if (clientRoles.status) {
                            resolve(clientRoles);
                        }

                        //admin case
                        if ('realm-management' in clientRoles) {

                            let URL2 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/groups';
                            config.url = URL2;

                            try {

                                let groups = await requestController.httpRequest(config, true);
                                delete config.url

                                groupsData = groups.data;
                                groupsData = groupsData.filter(group => !group.name.includes('_permission'));


                            } catch (er) {

                                let error = await this.checkErrorType(er);
                                reject(error);
                            }

                        } else {

                            //agent case
                            if ((keycloakObj.supervisedTeams).length == 0) {

                                resolve([]);

                                //supervisor case
                            } else {

                                //if no group ids are provided, send all the users of groups this user supervises.
                                if (groupsIdsArr.length == 0) {

                                    let supervisedGroups = keycloakObj.supervisedTeams;
                                    supervisedGroups = supervisedGroups.filter(group => !group.teamName.includes('_permission'));
                                    groupsData = supervisedGroups;

                                    //only send the users of provided groups.
                                } else {

                                    let groupsArr = [];
                                    let idsArr = groupsIdsArr;

                                    idsArr.forEach(id => {
                                        let group = keycloakObj.supervisedTeams.find(group => {
                                            return group.teamId == id;
                                        });

                                        if (!group) {

                                            message = `Given User doesn't suprvise any group against id: ${id}`;

                                            resolve({
                                                "status": 404,
                                                "message": message
                                            });
                                        }

                                        groupsArr.push(group);
                                    });

                                    groupsArr = groupsArr.filter(group => !group.teamName.includes('_permission'));
                                    groupsData = groupsArr;
                                }
                            }
                        }

                        allUsers = await teamsService.getUsersOfGroups(groupsData, config, keycloakConfig);
                        resolve(allUsers);

                    } catch (er) {
                        console.log(er);
                        let error = await this.checkErrorType(er);
                        console.log(error);
                        reject(error);
                    }


                }

                message = 'Please pass the valid arguments. First argument must be  (should not be empty object,' +
                    'must contain valid key-value pair) and Second argument must be Array of groupIds (could be an empty array)' +
                    '3rd Argument must be valid Access Token of current logged-in user.';

                resolve({
                    "status": 400,
                    "message": message
                });

            } catch (er) {

                let error = await this.checkErrorType(er);
                reject(error);
            };
        });

    }

    // this function requires comma separated list of roles in parameter e.g ["robot","human","customer"];
    getUsersByRole(keycloak_roles) {
        return new Promise(async (resolve, reject) => {
            let token;
            var URL = keycloakConfig["auth-server-url"] + 'realms/master/protocol/openid-connect/token'
            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    username: 'admin',
                    password: 'admin',
                    client_id: 'admin-cli',
                    grant_type: keycloakConfig.GRANT_TYPE || 'password',
                },
            };
            try {
                //  T.O.K.E.N   R.E.Q.U.E.S.T   # 1   ( P.E.R.M.I.S.S.I.O.N.S   N.O.T    I.N.C.L.U.D.E.D) 
                let adminTokenResponse = await requestController.httpRequest(config, true);
                if (adminTokenResponse.data.access_token) {
                    token = adminTokenResponse.data.access_token;
                    delete config.data;
                    config.method = 'get';
                    config.headers.Authorization = "Bearer " + token;
                    let userObject = {} // to read data object having all users of a certain role
                    let count = 0;
                    let flag = true;
                    let obj = [];  // final object to be returned

                    for (let i = 0; i < keycloak_roles.length; i++) {
                        try {

                            config.url = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/roles/' + keycloak_roles[i] + '/users?max=100000'
                            let getUsersfromRoles = await requestController.httpRequest(config, true);
                            userObject = getUsersfromRoles.data;

                            userObject.forEach((user) => {

                                if (count > 0) {

                                    let userIndex = obj.findIndex(usr => {
                                        return usr.username == user.username;
                                    });

                                    if (userIndex != -1) {
                                        obj[userIndex].roles.push(keycloak_roles[i]);
                                        flag = false;
                                    }
                                }

                                if (flag == true) {

                                    obj.push({
                                        'id': user.id,
                                        'username': user.username,
                                        'firstName': ((user.firstName == undefined) ? "" : user.firstName),
                                        'lastName': ((user.lastName == undefined) ? "" : user.lastName),
                                        'roles': [keycloak_roles[i]]
                                    })

                                }

                                flag = true;

                            });

                        }
                        catch (er) {
                            reject(er);
                        }

                        count++;
                    }
                    resolve(obj);
                }
                else {
                    reject("Access Token Request Failed");
                }
            }
            catch (err) {
                reject(err);
            }
        });
    }


    async getRealmRoles(adminToken) {

        return new Promise(async (resolve, reject) => {

            let URL = `${keycloakConfig["auth-server-url"]}${keycloakConfig["USERNAME_ADMIN"]}/realms/${keycloakConfig["realm"]}/roles`;



            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Bearer ${adminToken}`
                },
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, false);
                resolve(tokenResponse);

            }
            catch (err) {
                reject({
                    "status": err.response.status,
                    "message": err.response.data.error_description
                });
            }

        });
    }



    async assignRoleToUser(userId, roles, adminToken) {

        return new Promise(async (resolve, reject) => {

            let URL = `${keycloakConfig["auth-server-url"]}${keycloakConfig["USERNAME_ADMIN"]}/realms/${keycloakConfig["realm"]}/users/${userId}/role-mappings/realm`;

            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${adminToken}`
                },
                data: roles
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, false);
                resolve(tokenResponse);

            }
            catch (err) {
                reject({
                    "status": err.response.status,
                    "message": err.response.data.error_description
                });
            }

        });
    }


    async createUser(username, password, token, userRoles) {

        let assignRole = [];
        let assignGroups = ['agents_permission', 'default'];

        return new Promise(async (resolve, reject) => {


            for (let group of assignGroups) {

                let URL2 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/groups?search=' + group;

                let config1 = {
                    method: 'get',
                    url: URL2,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                };

                try {
                    let groupData = await requestController.httpRequest(config1, true);

                    if (groupData.data.length == 0) {

                        let createdGroup = await this.createGroup(token, group);

                    }
                } catch (err) {
                    reject({
                        "status": err.response.status,
                        "message": err.response.data.error_description
                    });
                }

            }


            let URL = `${keycloakConfig["auth-server-url"]}${keycloakConfig["USERNAME_ADMIN"]}/realms/${keycloakConfig["realm"]}/users`;

            let data = {
                username: username,
                enabled: true,
                credentials: [
                    {
                        type: 'password',
                        value: password,
                        temporary: false
                    }
                ],
                groups: ["agents_permission", "default"]
            }

            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                data: data
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, false);

                if (userRoles != []) {
                    //Get the user id at time of creation
                    let userLocation = tokenResponse.headers.location;
                    let userLocationSplit = userLocation.split("/");
                    let userId = userLocationSplit[(userLocationSplit.length) - 1];


                    //Get list of all the roles in keycloak realm
                    let realmRoles = await this.getRealmRoles(token);

                    //checking whether role exist in realmRoles object array:
                    for (let role of realmRoles.data) {

                        userRoles.forEach(userRole => {

                            if (role.name == userRole.toLocaleLowerCase()) {
                                assignRole.push({
                                    id: role.id,
                                    name: role.name
                                });
                            }

                        });
                    }

                    //assigning role to user
                    let roleAssigned = await this.assignRoleToUser(userId, assignRole, token);

                    //Role assigned with status 
                    if (roleAssigned.status == 204) {
                        resolve(tokenResponse);
                    }

                } else {

                    resolve(tokenResponse);

                }


            }
            catch (err) {
                reject({
                    "status": err.response.status,
                    "message": err.response.data.error_description
                });
            }

        });
    }

    async createFinesseUser(userObject, token) {

        let assignRole = [];

        return new Promise(async (resolve, reject) => {


            let URL = `${keycloakConfig["auth-server-url"]}${keycloakConfig["USERNAME_ADMIN"]}/realms/${keycloakConfig["realm"]}/users`;

            let data = {
                username: userObject.username,
                firstName: userObject.firstName,
                lastName: userObject.lastName,
                enabled: true,
                credentials: [
                    {
                        type: 'password',
                        value: '123456',
                        temporary: false
                    }
                ],
                groups: userObject.group
            }

            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                data: data
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, false);
                let userRoles = userObject.roles;

                if (userRoles != []) {
                    //Get the user id at time of creation
                    let userLocation = tokenResponse.headers.location;
                    let userLocationSplit = userLocation.split("/");
                    let userId = userLocationSplit[(userLocationSplit.length) - 1];


                    //Get list of all the roles in keycloak realm
                    let realmRoles = await this.getRealmRoles(token);

                    //checking whether role exist in realmRoles object array:
                    for (let role of realmRoles.data) {

                        userRoles.forEach(userRole => {

                            if (role.name == userRole.toLocaleLowerCase()) {

                                assignRole.push({
                                    id: role.id,
                                    name: role.name
                                });
                            }

                        });
                    }

                    //assigning role to user
                    let roleAssigned = await this.assignRoleToUser(userId, assignRole, token);

                    //Role assigned with status 
                    if (roleAssigned.status == 204) {
                        resolve(tokenResponse);
                    }

                } else {

                    resolve(tokenResponse);

                }


            }
            catch (err) {
                reject({
                    "status": err.response.status,
                    "message": err.response.data.error_description
                });
            }

        });
    }

    async createGroup(adminToken, groupName) {

        return new Promise(async (resolve, reject) => {

            let URL = `${keycloakConfig["auth-server-url"]}${keycloakConfig["USERNAME_ADMIN"]}/realms/${keycloakConfig["realm"]}/groups`;

            let data = {
                name: groupName
            }


            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Authorization': `Bearer ${adminToken}`
                },
                data: data
            };

            try {

                let createdGroup = await requestController.httpRequest(config, false);
                resolve(createdGroup.data);

            } catch (err) {
                reject({
                    "status": err.response.status,
                    "message": err.response.data.error_description
                });
            }

        });

    }

    async syncCiscoTeams(administratorUsername, administratorPassword, finesseUrl) {

        return new Promise(async (resolve, reject) => {

            //admin token url
            let token;
            let createdGroups;
            let groupSupervisors = [];
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token';

            //request config to fetch admin token
            var config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: keycloakConfig.CLIENT_ID,
                    username: keycloakConfig.USERNAME_ADMIN,
                    password: keycloakConfig.PASSWORD_ADMIN,
                    grant_type: keycloakConfig.GRANT_TYPE,
                    client_secret: keycloakConfig.credentials.secret
                }
            };

            try {

                //http request to fetch admin token
                let adminTokenResponse = await requestController.httpRequest(config, true);
                token = adminTokenResponse.data.access_token;

                //Service to get all existing keycloak groups
                let groupsList = await teamsService.getGroupsList(token, keycloakConfig);
                let groupNames = null;

                if (groupsList != null) {
                    groupNames = groupsList.map(group => group.name);
                }

                //service to get all the teams from Cisco Finesse
                let teamsList = await finesseService.getCiscoTeams(administratorUsername, administratorPassword, finesseUrl);

                //Converting the XML String returned from Finesse to JS Object
                parseXMLString(teamsList, async (err, result) => {
                    if (err) {
                        console.error(err);
                    } else {

                        //iterating through the Cisco finesse teams
                        for (let team of result.Teams.Team) {

                            //Converting both finesse teams and keycloak teams to lowercase for non case sensitive comparison
                            let isExist = groupNames.map(group => group.toLowerCase()).includes((team.name[0]).toLowerCase());

                            //Creating new group on keycloak side against finesse team if doesn't exist already.
                            if (!isExist) {
                                let newGroup = await this.createGroup(token, team.name[0]);
                            }

                        }

                        //Get the list of newly created groups in keycloak. We use it later to add supervisor to group
                        groupsList = await teamsService.getGroupsList(token, keycloakConfig);
                        groupNames = null;

                        if (groupsList != null) {
                            groupNames = groupsList.map(group => {
                                return {
                                    id: group.id,
                                    name: group.name
                                }
                            });
                        }

                        //Service to get all existing keycloak users
                        let usersList = await teamsService.getUsersList(token, keycloakConfig);
                        let userNames = null;

                        if (usersList != null) {
                            userNames = usersList.map(user => user.username);
                        }

                        //service to get existing users list from Cisco Finesse
                        let ciscoUsersList = await finesseService.getCiscoUsers(administratorUsername, administratorPassword, finesseUrl);

                        parseXMLString(ciscoUsersList, async (err, result) => {

                            if (err) {
                                console.error(err);
                            } else {

                                for (let user of result.Users.User) {

                                    //Converting both finesse user and keycloak user to lowercase for non case sensitive comparison
                                    let isExist = userNames.map(user => user.toLowerCase()).includes((user.loginName[0]).toLowerCase());

                                    //Creating new user on keycloak side against finesse user if doesn't exist already.
                                    if (!isExist) {

                                        let userObject = {
                                            username: user.loginName[0],
                                            firstName: user.firstName[0],
                                            lastName: user.lastName[0],
                                            roles: (user.roles[0].role).map(role => role.toLowerCase()),
                                            group: (user.teamName == '' || user.teamName == null) ? ['Default'] : user.teamName
                                        }

                                        if (user.teams) {
                                            if (user.teams[0].Team) {
                                                userObject.supervisedGroups = (user.teams[0].Team).map(team => team.name[0]);


                                                userObject.supervisedGroups.forEach(groupName => {


                                                    let keycloakGroupToSupervise = groupNames.find(group => group.name == groupName);
                                                    let isExistGroup = groupSupervisors.findIndex(group => group.name == groupName);

                                                    if (isExistGroup == -1) {
                                                        groupSupervisors.push({
                                                            id: keycloakGroupToSupervise.id,
                                                            name: keycloakGroupToSupervise.name,
                                                            supervisors: [`${userObject.username}`]
                                                        })
                                                    } else {
                                                        groupSupervisors[isExistGroup].supervisors[0] += `,${userObject.username}`;
                                                    }
                                                });

                                            }
                                        }

                                        let newUser = await this.createFinesseUser(userObject, token);
                                    }

                                }

                                if (groupSupervisors.length != 0) {
                                    //Assigning Groups to Supervisors
                                    let assignedSupervisors = await teamsService.addSupervisorToGroup(groupSupervisors, token, keycloakConfig);
                                }

                            }

                        });


                        resolve('All Groups Created');
                    }
                });


            } catch (er) {

                let error = await this.checkErrorType(er);
                reject(error);
            }
        });
    }

    //Authenticating Finesse User
    async authenticateFinesse(username, password, finesseUrl, userRoles, finesseToken) {

        //Authentication of Finesse User, it returns a status code 200 if user found and 401 if unauthorized.
        let finesseLoginResponse;

        if (finesseToken.length == 0) {
            finesseLoginResponse = await finesseService.authenticateUserViaFinesse(username, password, finesseUrl);

        } else {
            finesseLoginResponse = await finesseService.authenticateUserViaFinesseSSO(username, finesseToken, finesseUrl);
        }

        //If user is SSO then password is not provided, we are setting up a pre-defined password.
        password = (password.length == 0) ? "123456" : password;

        let authenticatedByKeycloak = false;
        let keycloakAuthToken = null;
        let timeoutErr = null;

        if (finesseLoginResponse.status == 200) {
            try {

                //Checking whether finesse user already exist in keycloak and fetch its token
                keycloakAuthToken = await this.getKeycloakTokenWithIntrospect(username, password, keycloakConfig["realm"]);
                authenticatedByKeycloak = true;

            } catch (err) {

                if (err.response.status == 401) {

                    console.log("User doesn't exist in Keycloak, syncing finesse user in keycloak...");

                } else {

                    throw ({
                        "status": err.response.status,
                        "message": err.response.data.error_description
                    });

                }

            } finally {

                //Finesse User not found in keycloak, so we are going to create one.
                if (!authenticatedByKeycloak) {

                    try {

                        //Fetching admin token, we pass it in our "Create User" API for authorization
                        keycloakAuthToken = await this.getKeycloakTokenWithIntrospect(keycloakConfig["USERNAME_ADMIN"], keycloakConfig["PASSWORD_ADMIN"], keycloakConfig["realm"]);
                    } catch (err) {

                        if (err.code == "ETIMEDOUT") {

                            throw ({
                                'Keycloak login status': 408,
                                'keycloak login message': `Keycloak server unaccessable against URL: ${keycloakConfig["auth-server-url"]}`
                            });

                        } else {
                            throw ({
                                "status": err.response.status,
                                "message": "Error While getting Keycloak admin token: " + err.response.data.error_description
                            });
                        }

                    }

                    if (keycloakAuthToken.token) {

                        let token = keycloakAuthToken.token;

                        //validating customer Before Creation
                        let { error, value } = validateUser({ username, password, token, userRoles });

                        if (error) {

                            throw ({
                                "status": 400,
                                "message": "Error while creation of user, error message: " + error.details[0].message
                            })
                        }
                    }

                    try {
                        //Creating Finesse User inside keycloak.
                        let userCreated = await this.createUser(username, password, keycloakAuthToken.token, userRoles);

                        if (userCreated.status == 201) {

                            //Returning the token of recently created User 
                            keycloakAuthToken = await this.getKeycloakTokenWithIntrospect(username, password, keycloakConfig["realm"]);
                        }


                    } catch (err) {

                        if (err.code == "ETIMEDOUT") {

                            throw ({
                                'Keycloak login status': 408,
                                'keycloak login message': `Keycloak server unaccessable against URL: ${keycloakConfig["auth-server-url"]}`
                            });

                        } else {

                            console.log(err);

                            throw ({
                                "status": err.response.status,
                                "message": "Error While creating Keycloak user: " + err.response.data.error_description
                            });
                        }
                    }
                }
            }

            return keycloakAuthToken;

        } else {

            return finesseLoginResponse

        }
    }

    async generateAccessTokenFromRefreshToken(refreshToken) {

        return new Promise(async (resolve, reject) => {
            let accessToken;
            var URL = keycloakConfig["auth-server-url"] + 'realms/' + keycloakConfig.realm + '/protocol/openid-connect/token'

            var config = {
                method: 'post',
                url: URL,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: keycloakConfig.CLIENT_ID,
                    client_secret: keycloakConfig.credentials.secret,
                    grant_type: 'refresh_token',
                    refresh_token: refreshToken
                }
            };

            try {
                let refreshTokenResponse = await requestController.httpRequest(config, true);

                let accessToken = refreshTokenResponse.data.access_token;
                resolve({
                    'status': 200,
                    'access_token': accessToken
                });

            } catch (error) {

                if (error.response) {

                    if (error.response.data.error_description == 'Token is not active') {
                        error.response.data.error_description = 'Refresh Token expired, please login again';
                    }

                    reject({
                        'status': error.response.status,
                        'message': `${error.response.data.error_description}`
                    });

                } else {
                    reject({ 'message': error.message });
                }
            }

        });
    }

    async checkErrorType(err) {

        if (err.code == "ETIMEDOUT") {

            return ({
                'Keycloak login status': 408,
                'keycloak login message': `Keycloak server unaccessable against URL: ${keycloakConfig["auth-server-url"]}`
            });

        } else {

            return ({
                "status": err.response.status,
                "message": "Error: " + err.response.data.error_description
            });
        }
    }

}

function validateUser(userData) {
    let schema = Joi.object({
        username: Joi.string().min(1).max(255).required(),
        password: Joi.string().min(1).max(255).required(),
        token: Joi.string().required(),
        userRoles: Joi.array().items(Joi.string()).allow(null)
    });

    return schema.validate(userData);
}

module.exports = KeycloakService;