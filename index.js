var session = require("express-session");
var Keycloak = require("keycloak-connect");
var requestController = require("./controller/requestController.js");
var config = require("../../config.json");
var memory = new session.MemoryStore();
var keycloakConfig = null;
class NodeAdapter extends Keycloak {
    constructor() {
        keycloakConfig =  {...config};

        super({ store: memory }, keycloakConfig);   //initialising keycloak-connect   //Keycloak = new Keycloak({store: memory}, config);

       // this.keycloakConfig = config;
    }

    // this function requires comma separated list of roles in parameter e.g ["robot","human","customer"];
    getUsersByRole = function getUsersByRole(keycloak_roles) {
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
                    let rolesCount = 0;
                    for (let i = 0; i < keycloak_roles.length; i++) {
                        try {
                            config.url = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/roles/' + keycloak_roles[i] + '/users'
                            let getUsersfromRoles = await requestController.httpRequest(config, true);
                            userObject = getUsersfromRoles.data;
                            for (let check = 0; check < userObject.length; check++) {
                                let tobecheckedID = userObject[check].id;
                                for (let org = 0; org < count; org++) {
                                    if (tobecheckedID === obj[org].id) {
                                        obj[org].roles[++rolesCount] = keycloak_roles[i];
                                        flag = false;
                                    }
                                }
                                if (flag == true) {
                                    obj[count] = {
                                        'id': userObject[check].id,
                                        'userName': userObject[check].username,
                                        'firstName': userObject[check].firstName,
                                        'lastName': userObject[check].lastName,
                                        'roles': [keycloak_roles[i]]
                                    }
                                    if (obj[count].firstName == undefined) {
                                        obj[count].firstName = "";
                                        obj[count].lastName = "";
                                    }
                                    count = count + 1;
                                }
                            }
                        }
                        catch (er) {
                            reject(er);
                        }
                    }
                    resolve(obj);
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
    // this function requires an Admin user in keycloak.json having realm-management roles
    authenticateUserViaKeycloak(user_name, user_password, realm_name) {

        return new Promise(async (resolve, reject) => {
            let token;
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
            //console.log(config);
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
                                            let finalObject = {
                                                'token': userToken,
                                                'keycloak_User': responseObject
                                            }
                                            resolve(finalObject);

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

    permitUsertoResource(resource_name, keycloak_user_id) {

        return new Promise(async (resolve, reject) => {
            let token;
            var userPolicyName = resource_name + "-policy";
            var resource_permissions = resource_name + "-permission";
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
                let URL3 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/clients/' + keycloakConfig.CLIENT_DB_ID + '/authz/resource-server/policy/user';
                config.url = URL3;
                config.headers['Content-Type'] = 'application/json';
                config.headers.Authorization = 'Bearer ' + token;
                config.data.decisionStrategy = 'UNANIMOUS';
                config.data.logic = "POSITIVE";
                config.data.name = userPolicyName;
                config.data.type = "user";
                config.data.id = userPolicyName;
                config.data.users = [keycloak_user_id];
                delete config.data["client_id"];
                delete config.data["client_secret"];
                delete config.data["grant_type"];
                delete config.data["username"];
                delete config.data["password"];
                config.data = JSON.stringify(config.data);
                try {
                    let policyResponse = await requestController.httpRequest(config, false);
                    config.data = JSON.parse(config.data);
                    //  A.S.S.O.C.I.A.T.E   P.E.R.M.I.S.S.I.O.N   T.O   A  R.E.S.O.U.R.C.E   ( U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y   I.S  A.S.S.O.C.I.A.T.E.D   T.O    P.E.R.M)  
                    config.data.name = resource_permissions;
                    config.data.type = "resource";
                    config.data.id = resource_permissions;
                    config.data.policies = [userPolicyName];
                    config.data.resources = [resource_name];
                    delete config.data["users"];
                    config.data = JSON.stringify(config.data);
                    let URL4 = keycloakConfig["auth-server-url"] + 'admin/realms/' + keycloakConfig.realm + '/clients/' + keycloakConfig.CLIENT_DB_ID + '/authz/resource-server/permission/resource';
                    config.url = URL4;
                    try {
                        let permissionResponse = await requestController.httpRequest(config, false);
                        resolve(permissionResponse);
                    } catch (error) {
                        reject("Permisssion not created" + error);
                    }
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
    revokeUseronResource = (resource_name, keycloak_user_id) => {
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
}
module.exports = { NodeAdapter };
