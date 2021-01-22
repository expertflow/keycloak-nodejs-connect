var express = require('express');
const requestController = require("./controller/requestController.js");
const env = require("../../keycloak.json");
var bodyParser = require('body-parser');
var app = express();
const qs = require('querystring');
const { Interface } = require('readline');

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());
class NodeAdapter {

    constructor() {}
    authenticateUserViaKeycloak(user_name, user_password) {

        return new Promise(async (resolve, reject) => {
            let token;
            var URL = 'http://' + env.HOST  + ':' + env.PORT + '/auth/realms/' + env.REALM + '/protocol/openid-connect/token'
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
                    client_id: env.CLIENT_ID,
                    client_secret: env.CLIENT_SECRET,
                    grant_type: env.GRANT_TYPE ,
                },
            };
            try {
                //  T.O.K.E.N   R.E.Q.U.E.S.T   # 1   ( P.E.R.M.I.S.S.I.O.N.S   N.O.T    I.N.C.L.U.D.E.D) 
                let tokenResponse = await requestController.httpRequest(config, Boolean(10 > 5));
                if (tokenResponse.data.access_token) {
                    token = tokenResponse.data.access_token;
                    config.data.grant_type = 'urn:ietf:params:oauth:grant-type:uma-ticket';
                    config.data.audience = env.CLIENT_ID;
                    config.headers.Authorization = "Bearer " + token;
                    //  T.O.K.E.N   R.E.Q.U.E.S.T   # 2   (A.C.C.E.S.S   T.O.K.E.N   W.I.T.H   P.E.R.M.I.S.S.I.O.N.S)                 
                    try {
                        var rptResponse = await requestController.httpRequest(config, Boolean(10 > 5));
                        if (rptResponse.data.access_token) {
                            token = rptResponse.data.access_token;
                            config.data.grant_type = env.GRANT_TYPE;
                            config.data.token = token;
                            URL = URL + '/introspect'
                            config.url = URL;
                     //  T.O.K.E.N   R.E.Q.U.E.S.T   # 3   (A.C.C.E.S.S   T.O.K.E.N   I.N.T.R.O.S.P.E.C.T.I.O.N)                 

                            try {
                                let intrsopectionResponse = await requestController.httpRequest(config, Boolean(10 > 5));
                                intrsopectionResponse.data.access_token = token;
                    //  T.O.K.E.N   R.E.Q.U.E.S.T   # 4   ( A.D.M.I.N.  T.O.K.E.N) 
                                try {
                                    config.data.username=env.USERNAME_ADMIN;
                                    config.data.password=env.PASSWORD_ADMIN;
                                    config.url = 'http://' + env.HOST + ':' + env.PORT + '/auth/realms/' + env.REALM + '/protocol/openid-connect/token';
                                    delete config.data.audience;
                                    delete config.data.token;
                                    delete config.headers.Authorization;
                                    let adminTokenResponse = await requestController.httpRequest(config, Boolean(10 > 9));
                                    if (adminTokenResponse.data.access_token) {
                                        token = adminTokenResponse.data.access_token;
                                        try {
                                            config.headers.Authorization = "Bearer " + token;
                                            config.method='get';
                                            config.url='http://' + env.HOST + ':' + env.PORT + '/auth/admin/realms/' + env.REALM + '/users?username=' + user_name;
                                            delete config.data;
                                            let getuserDetails = await requestController.httpRequest(config, Boolean(10 > 9));
                                            let responseObject = {
                                                'id': getuserDetails.data[0].id,
                                                'firstName':getuserDetails.data[0].firstName,
                                                'lastName':getuserDetails.data[0].lastName,
                                                'username':getuserDetails.data[0].username,
                                                'permittedResources': {
                                                   'Resources': intrsopectionResponse.data.authorization.permissions
                                                },
                                                'roles': intrsopectionResponse.data.realm_access.roles,
                                                'realm': env.REALM

                                            };
                                            resolve(responseObject);

                                        }
                                        catch(error){
                                            reject("Get all users request not sent"+error);
                                        }
                                    }
                                    else{
                                        reject("Admin token Request Failed");

                                    }
                                }
                                catch(error){
                                    reject("Admin Request not sent"+error);
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

    createResource(resource_name, resource_scope = env.SCOPE_NAME) {
        return new Promise(async (resolve, reject) => {

            var URL = 'http://' + env.HOST  + ':' + env.PORT + '/auth/realms/' + env.REALM + '/protocol/openid-connect/token'
            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: env.CLIENT_ID,
                    client_secret: env.CLIENT_SECRET,
                    grant_type: env.GRANT_TYPE_PAT
                },
            };
            //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1     
            try {
                let patToken = await requestController.httpRequest(config, Boolean(10 > 9));
                if (patToken.data.access_token) {
                    let token = patToken.data.access_token;
                    //     C.R.E.A.T.E    R.E.S.O.U.R.C.E     R.E.Q.U.E.S.T   
                    delete config.data["client_id"];
                    delete config.data["client_secret"];
                    delete config.data["grant_type"];

                    config.data.name = resource_name;
                    config.data._id = resource_name;
                    config.data.resource_scopes = [resource_scope];

                    config.url = 'http://' + env.HOST  + ':' + env.PORT + '/auth/realms/' + env.REALM + '/authz/protection/resource_set';
                    config.headers.Authorization = "Bearer " + token;
                    config.headers['Content-Type'] = 'application/json';

                    try {
                        let resourceResponse = await requestController.httpRequest(config, Boolean(10 > 14));
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
            var URL = 'http://' + env.HOST  + ':' + env.PORT + '/auth/realms/' + env.REALM + '/protocol/openid-connect/token';
            let config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: env.CLIENT_ID ,
                    client_secret: env.CLIENT_SECRET ,
                    grant_type: env.GRANT_TYPE_PAT
                },
            };
            //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1      
            try {
                let patToken = await requestController.httpRequest(config, Boolean(10 > 9));
                if (patToken.data.access_token) {
                     token = patToken.data.access_token;
                    //  D.E.L.E.T.E    R.E.S.O.U.R.C.E  A.N.D   P.E.R.M.I.S.S.I.O.N   R.E.Q.U.E.S.T   
                    let URL1 = 'http://' + env.HOST  + ':' + env.PORT + '/auth/realms/' + env.REALM + '/authz/protection/resource_set/' + resource_name;
                    config.url = URL1;
                    config.method = 'delete';
                    config.headers.Authorization = 'Bearer ' + token;
                    delete config.data["grant_type"];
                    config.data.name = resource_name;
                    try {
                        let resourceResponse = await requestController.httpRequest(config, Boolean(10 > 9));
                        //         // WE NEED admin token to delete policy
                        //         /// admin token request
                        config.method = 'post';
                        config.url = URL;
                        delete config.headers["Authorization"];
                        config.data.client_id = env.CLIENT_ID;
                        config.data.username = env.USERNAME_ADMIN;
                        config.data.password = env.PASSWORD_ADMIN;
                        config.data.grant_type = env.GRANT_TYPE;
                        config.data.client_secret = env.CLIENT_SECRET;
                        try {
                            let adminTokenResponse = await requestController.httpRequest(config, Boolean(12 > 11));
                            token = adminTokenResponse.data.access_token;
                            // now deleting policy
                            config.method='delete';
                            delete config.data;
                            let URL6 =   'http://' + env.HOST  + ':' + env.PORT + '/auth/admin/realms/' + env.REALM + '/clients/' + env.CLIENT_DB_ID + '/authz/resource-server/policy/user/' + resource_name + '-policy';
                            config.url=URL6;
                            delete config.headers['Accept'];
                            delete config.headers['cache-control'];
                            delete config.headers['Content-Type'];
                            config.headers.Authorization='Bearer ' + token;
                            try {
                                let deletePolicy = await requestController.httpRequest(config, Boolean(10 > 11));
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
            var URL = 'http://' + env.HOST  + ':' + env.PORT + '/auth/realms/' + env.REALM + '/protocol/openid-connect/token'
            var config = {
                method: 'post',
                url: URL,
                headers: {
                    'Accept': 'application/json',
                    'cache-control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                data: {
                    client_id: env.CLIENT_ID,
                    username: env.USERNAME_ADMIN,
                    password:env.PASSWORD_ADMIN,
                    grant_type: env.GRANT_TYPE,
                    client_secret: env.CLIENT_SECRET
                }
            };
            try {
                let adminTokenResponse = await requestController.httpRequest(config, Boolean(10 > 9));
                token = adminTokenResponse.data.access_token;
                //   T.O.K.E.N    R.E.Q.U.E.S.T  (user with admin is already defined in keycloak with roles 'realm-management')
                //   //  C.R.E.A.T.E    U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y  
                let URL3 = 'http://' + env.HOST  + ':' + env.PORT + '/auth/admin/realms/' + env.REALM + '/clients/' + env.CLIENT_DB_ID + '/authz/resource-server/policy/user';
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
                config.data =JSON.stringify(config.data);
                try {
                    let policyResponse = await requestController.httpRequest(config, Boolean(10 > 11));
                    config.data =JSON.parse(config.data);
                    //  A.S.S.O.C.I.A.T.E   P.E.R.M.I.S.S.I.O.N   T.O   A  R.E.S.O.U.R.C.E   ( U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y   I.S  A.S.S.O.C.I.A.T.E.D   T.O    P.E.R.M)  
                    config.data.name = resource_permissions;
                    config.data.type = "resource";
                    config.data.id = resource_permissions;
                    config.data.policies=[userPolicyName];
                    config.data.resources=[resource_name];
                    delete config.data["users"];
                    config.data =JSON.stringify(config.data);
                    let URL4 = 'http://' + env.HOST  + ':' + env.PORT + '/auth/admin/realms/' + env.REALM + '/clients/' + env.CLIENT_DB_ID + '/authz/resource-server/permission/resource';
                    config.url = URL4;
                    try {
                        let permissionResponse = await requestController.httpRequest(config, Boolean(10 > 11));
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
                    client_id: env.CLIENT_ID,
                    username: env.USERNAME_ADMIN,
                    password:env.PASSWORD_ADMIN,
                    grant_type: env.GRANT_TYPE,
                    client_secret: env.CLIENT_SECRET
                }
            };
            try {
                let adminTokenResponse = await requestController.httpRequest(config,Boolean(11>10));
                token = adminTokenResponse.data.access_token;
                // EVALUATION REQUEST
                var data = JSON.stringify({
                     "resources": [{ "_id": resource_name }],
                     "clientId": env.CLIENT_DB_ID, 
                     "userId": keycloak_user_id 
                    });
                    config.data.clientId = env.CLIENT_DB_ID;
                    config.data.resources=[{ "_id": resource_name }];
                    config.data.userId=  keycloak_user_id;
                    delete config.data["username"];
                    delete config.data["password"];
                    delete config.data["grant_type"];
                    delete config.data["client_secret"];
                    delete config.data["client_id"];
                   let URL5= 'http://' + env.HOST  + ':' + env.PORT + '/auth/admin/realms/' + env.REALM + '/clients/' + env.CLIENT_DB_ID + '/authz/resource-server/policy/evaluate';
                    config.url=URL5;
                    config.headers['Content-Type']='application/json';
                    config.headers.Authorization='Bearer ' + token,
                    config.data =JSON.stringify(config.data);
                
                try {
                    let evaluationResponse = await requestController.httpRequest(config, Boolean(10 > 11));
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
                        client_id: env.CLIENT_ID,
                        username: env.USERNAME_ADMIN,
                        password:env.PASSWORD_ADMIN,
                        grant_type: env.GRANT_TYPE,
                        client_secret: env.CLIENT_SECRET
                    }
                };
                try {
                    let adminTokenResponse = await requestController.httpRequest(config, Boolean(12 > 11));
                    token = adminTokenResponse.data.access_token;
                    // now deleting policy
                    config.method='delete';
                    delete config.data;
                    let URL6 =   'http://' + env.HOST  + ':' + env.PORT + '/auth/admin/realms/' + env.REALM + '/clients/' + env.CLIENT_DB_ID + '/authz/resource-server/policy/user/' + resource_name + '-policy';
                    config.url=URL6;
                    delete config.headers['Accept'];
                    delete config.headers['cache-control'];
                    delete config.headers['Content-Type'];
                    config.headers.Authorization='Bearer ' + token;
                    try {
                        let deletePolicy = await requestController.httpRequest(config, Boolean(10 > 11));
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
module.exports.NodeAdapter = new NodeAdapter;
