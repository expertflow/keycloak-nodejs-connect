var session = require( "express-session" );
var Keycloak = require( "keycloak-connect" );
const Joi = require( "joi" );
const parseXMLString = require( "xml2js" ).parseString;

var requestController = require( "../controller/requestController.js" );
var memory = new session.MemoryStore();

var keycloakConfig = null;
let realmRoles = [];

const FinesseService = require( "./finesseService" );
const TeamsService = require( "./teamsService" );
const ErrorService = require( './errorService.js' );

const finesseService = new FinesseService();
const teamsService = new TeamsService();
const errorService = new ErrorService();

class KeycloakService extends Keycloak {
  constructor ( config ) {
    keycloakConfig = { ...config };
    super( { store: memory }, keycloakConfig ); //initialising keycloak-connect   //Keycloak = new Keycloak({store: memory}, config);
    // this.keycloakConfig = config;
  }

  //Based on the attributes it either authenticate keycloak user or finesse user.
  async authenticateUserViaKeycloak( user_name, user_password, realm_name, finesseUrl, userRoles, finesseToken ) {

    let token = "";

    // If finesseUrl is empty it means normal keycloak auth is required.
    if ( finesseUrl == "" ) {

      token = await this.getKeycloakTokenWithIntrospect( user_name, user_password, realm_name );
      return token;

    } else {

      // Finesse Auth, takes userRole in argument to create user along with role.
      token = await this.authenticateFinesse( user_name, user_password, finesseUrl, userRoles, finesseToken );
      return token;

    }
  }

  async getAccessToken( user_name, user_password ) {

    return new Promise( async ( resolve, reject ) => {

      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig[ "realm" ] + "/protocol/openid-connect/token";

      let config = {
        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
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

        let tokenResponse = await requestController.httpRequest( config, true );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {
          error_message: "Error Occured While Generating User Access Token",
          error_detail: error
        } );

      }
    } );
  }

  async getTokenRPT( user_name, user_password, access_token ) {

    return new Promise( async ( resolve, reject ) => {

      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig[ "realm" ] + "/protocol/openid-connect/token";

      let config = {
        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": `Bearer ${access_token}`
        },
        data: {
          username: user_name,
          password: user_password,
          client_id: keycloakConfig.CLIENT_ID,
          client_secret: keycloakConfig.credentials.secret,
          grant_type: "urn:ietf:params:oauth:grant-type:uma-ticket",
          audience: keycloakConfig.CLIENT_ID
        },
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, true );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {
          error_message: "Error Occured While Generating User RPT Token",
          error_detail: error
        } );

      }
    } );
  }

  async getIntrospectToken( access_token ) {

    return new Promise( async ( resolve, reject ) => {

      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig[ "realm" ] + "/protocol/openid-connect/token/introspect";

      let config = {
        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          client_secret: keycloakConfig.credentials.secret,
          grant_type: keycloakConfig.GRANT_TYPE,
          token: access_token
        },
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, true );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {
          error_message: "Error Occured While Generating User Introspect Token",
          error_detail: error
        } );

      }
    } );
  }

  // this function requires an Admin user in keycloak.json having realm-management roles
  async getKeycloakTokenWithIntrospect( user_name, user_password, realm_name ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let refresh_token;
      let error;

      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + realm_name + "/protocol/openid-connect/token";

      //keycloakConfig["auth-server-url"] +'realms
      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
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
        let tokenResponse = await requestController.httpRequest( config, true );

        if ( tokenResponse.data.access_token ) {

          token = tokenResponse.data.access_token;
          config.data.grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket";
          config.data.audience = keycloakConfig.CLIENT_ID;
          config.headers.Authorization = "Bearer " + token;

          //  T.O.K.E.N   R.E.Q.U.E.S.T   # 2   (A.C.C.E.S.S   T.O.K.E.N   W.I.T.H   P.E.R.M.I.S.S.I.O.N.S)
          try {

            var rptResponse = await requestController.httpRequest( config, true );

            if ( rptResponse.data.access_token ) {

              token = rptResponse.data.access_token;
              refresh_token = rptResponse.data.refresh_token;

              var userToken = token;
              config.data.grant_type = keycloakConfig.GRANT_TYPE;
              config.data.token = token;
              URL = URL + "/introspect";
              config.url = URL;

              //  T.O.K.E.N   R.E.Q.U.E.S.T   # 3   (A.C.C.E.S.S   T.O.K.E.N   I.N.T.R.O.S.P.E.C.T.I.O.N)
              try {

                let intrsopectionResponse = await requestController.httpRequest( config, true );
                intrsopectionResponse.data.access_token = token;

                //  T.O.K.E.N   R.E.Q.U.E.S.T   # 4   ( A.D.M.I.N.  T.O.K.E.N)
                try {

                  config.data.username = keycloakConfig.USERNAME_ADMIN;
                  config.data.password = keycloakConfig.PASSWORD_ADMIN;
                  config.url = keycloakConfig[ "auth-server-url" ] + "realms/" + realm_name + "/protocol/openid-connect/token";

                  delete config.data.audience;
                  delete config.data.token;
                  delete config.headers.Authorization;

                  let adminTokenResponse = await requestController.httpRequest( config, true );

                  if ( adminTokenResponse.data.access_token ) {

                    token = adminTokenResponse.data.access_token;

                    try {

                      config.headers.Authorization = "Bearer " + token;
                      config.method = "get";
                      config.url = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + realm_name + "/users?username=" + user_name;
                      delete config.data;

                      let getuserDetails = await requestController.httpRequest( config, true );

                      if ( getuserDetails.data.length !== 0 ) {

                        let responseObject = {

                          id: getuserDetails.data[ 0 ].id,
                          firstName: getuserDetails.data[ 0 ].firstName ? getuserDetails.data[ 0 ].firstName : "",
                          lastName: getuserDetails.data[ 0 ].lastName ? getuserDetails.data[ 0 ].lastName : "",
                          username: getuserDetails.data[ 0 ].username,
                          permittedResources: {
                            Resources: intrsopectionResponse.data.authorization.permissions,
                          },
                          roles: intrsopectionResponse.data.realm_access.roles,
                          realm: realm_name,

                        };

                        //Adding user custom attribute to our token object data.
                        if ( getuserDetails.data[ 0 ].attributes ) {

                          responseObject.attributes = getuserDetails.data[ 0 ].attributes;
                        } else {

                          responseObject.attributes = {};
                        }

                        delete config.headers.Authorization;
                        delete config.data;

                        //Fetching Groups data for each user.
                        try {

                          let teamData = await this.getUserSupervisedGroups( responseObject.id, responseObject.username, responseObject.roles, token );

                          //Getting role against permission group
                          let isRole = ( teamData.permissionGroups ) ? ( ( teamData.permissionGroups.includes( "agents_permission" ) &&
                            teamData.permissionGroups.includes( "senior_agents_permission" ) ? [ 'agent', 'supervisor' ] : [ 'agent' ] ) ) : undefined;

                          let hasRole;

                          if ( isRole ) {
                            hasRole = isRole.some( requiredRole => responseObject.roles.includes( requiredRole ) );
                          }


                          //checking if required roles are assigned to user or not.
                          if ( isRole && !hasRole ) {

                            reject( {
                              error_message: "Error Occured While Generating User Access Token",
                              error_detail: {
                                status: 403,
                                reason: ( isRole.length > 1 ) ?
                                  `Assign Either of ${isRole} role, if User is Senior Agent then Assign agent role else if user is Supervisor then assign supervisor role` :
                                  `${isRole} Role has not been assigned, Please assign ${isRole} Role to given User.`
                              }
                            } );
                          }


                          delete teamData.permissionGroups;

                          responseObject.userTeam = teamData.userTeam;
                          responseObject.supervisedTeams = teamData.supervisedTeams;
                          responseObject.secondarySupervisedTeams = teamData.secondarySupervisedTeams;

                          let finalObject = {

                            token: userToken,
                            refresh_token: refresh_token,
                            keycloak_User: responseObject,

                          };

                          resolve( finalObject );

                        } catch ( er ) {

                          reject( er );
                        }

                      } else {

                        reject( {
                          error_message: "Error Occured While Fetching User Details During Login Process",
                          error_detail: {
                            status: 404,
                            reason: `No User exists against provided Username: ${user_name}`
                          }
                        } );

                      }


                    } catch ( er ) {

                      error = await errorService.handleError( er );

                      reject( {
                        error_message: "Error Occured While Fetching User Details During Login Process",
                        error_detail: error
                      } );
                    }
                  }

                } catch ( er ) {

                  error = await errorService.handleError( er );

                  reject( {
                    error_message: "Error Occured While Generating Admin Access Token required for User Authentication Flow",
                    error_detail: error
                  } );

                }

              } catch ( er ) {

                error = await errorService.handleError( er );

                reject( {
                  error_message: "Error Occured While Generating Introspect Token",
                  error_detail: error
                } );

              }

            }

          } catch ( er ) {

            error = await errorService.handleError( er );

            reject( {
              error_message: "Error while fetching RPT token, Please make sure all required Roles,Permissions & " +
                "Groups are assigned to User. e.g: Agent user must be assigned agent role, agents_permission group & all required permissions are created" +
                ". Every user must be assigned one team, if user is not part of any Team then assign default team to User",
              error_detail: error
            } );

          }

        }

      } catch ( er ) {

        error = await errorService.handleError( er );

        reject( {
          error_message: "Error Occured While Generating User Access Token",
          error_detail: error
        } );

      }
    } );
  }

  async getUserInfoFromToken( username, token ) {

    return new Promise( async ( resolve, reject ) => {

      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token/introspect";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          username: username,
          client_id: keycloakConfig.CLIENT_ID,
          client_secret: keycloakConfig.credentials.secret,
          token: token,
        },

      };

      try {

        let userInfo = await requestController.httpRequest( config, true );

        if ( !userInfo.data.active ) {

          reject( {
            error_message: "Error Occured While Getting User Info From Token",
            error_detail: {
              status: 401,
              reason: `Provided Access Token Expired. Please Provide Valid Access Token`
            }
          } );

        }

        let clientRoles = userInfo.data.resource_access;
        resolve( clientRoles );

      } catch ( er ) {

        error = await errorService.handleError( er );

        reject( {
          error_message: "Error Occured While Getting User Info From Token",
          error_detail: error
        } );
      }

    } );
  }

  //Client ID is required for Authorization Functionality
  async getClientId( token ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig[ "realm" ] + "/clients?clientId=" + keycloakConfig[ "CLIENT_ID" ];

      var config = {
        method: "get",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        headers: {
          Authorization: "Bearer " + token,
        },
      };

      try {

        let result = await requestController.httpRequest( config, false );
        let clientId = result.data[ 0 ].id;

        resolve( clientId );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Fetching ClientID in ClientID Component.",
          error_detail: error
        } );

      }

    } );
  }

  createResource( resource_name, resource_scope = keycloakConfig.SCOPE_NAME ) {

    return new Promise( async ( resolve, reject ) => {

      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          client_secret: keycloakConfig.credentials.secret,
          grant_type: keycloakConfig.GRANT_TYPE_PAT,
        },

      };

      //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1
      try {

        let patToken = await requestController.httpRequest( config, true );

        if ( patToken.data.access_token ) {

          let token = patToken.data.access_token;
          //     C.R.E.A.T.E    R.E.S.O.U.R.C.E     R.E.Q.U.E.S.T
          delete config.data[ "client_id" ];
          delete config.data[ "client_secret" ];
          delete config.data[ "grant_type" ];

          config.data.name = resource_name;
          config.data._id = resource_name;
          config.data.resource_scopes = [ resource_scope ];

          config.url = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/authz/protection/resource_set";
          config.headers.Authorization = "Bearer " + token;
          config.headers[ "Content-Type" ] = "application/json";

          try {

            let resourceResponse = await requestController.httpRequest( config, false );
            resolve( resourceResponse );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Error Occured While Creating Resource",
              error_detail: error
            } );

          }

        }

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating P.A.T Token",
          error_detail: error
        } );

      }
    } );

  }

  deleteResource( resource_name ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          client_secret: keycloakConfig.credentials.secret,
          grant_type: keycloakConfig.GRANT_TYPE_PAT,
        },

      };

      //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1
      try {

        let patToken = await requestController.httpRequest( config, true );

        if ( patToken.data.access_token ) {

          token = patToken.data.access_token;
          //  D.E.L.E.T.E    R.E.S.O.U.R.C.E  A.N.D   P.E.R.M.I.S.S.I.O.N   R.E.Q.U.E.S.T
          let URL1 = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/authz/protection/resource_set/" + resource_name;

          config.url = URL1;
          config.method = "delete";
          config.headers.Authorization = "Bearer " + token;
          delete config.data[ "grant_type" ];
          config.data.name = resource_name;

          try {

            let resourceResponse = await requestController.httpRequest( config, true );

            //         // WE NEED admin token to delete policy
            //         /// admin token request
            config.method = "post";
            config.url = URL;
            delete config.headers[ "Authorization" ];
            config.data.client_id = keycloakConfig.CLIENT_ID;
            config.data.username = keycloakConfig.USERNAME_ADMIN;
            config.data.password = keycloakConfig.PASSWORD_ADMIN;
            config.data.grant_type = keycloakConfig.GRANT_TYPE;
            config.data.client_secret = keycloakConfig.credentials.secret;

            try {

              let adminTokenResponse = await requestController.httpRequest( config, true );
              token = adminTokenResponse.data.access_token;

              // now deleting policy
              config.method = "delete";
              delete config.data;
              let URL6 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/clients/" + keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/user/" + resource_name + "-policy";
              config.url = URL6;

              delete config.headers[ "Accept" ];
              delete config.headers[ "cache-control" ];
              delete config.headers[ "Content-Type" ];
              config.headers.Authorization = "Bearer " + token;

              try {

                let deletePolicy = await requestController.httpRequest( config, false );
                resolve( deletePolicy );

              } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                  error_message: "Error Occured While Deleting Auth Policy in Delete Resource",
                  error_detail: error
                } );
              }

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Error Occured While Generating Admin Token in Delete Resource",
                error_detail: error
              } );

            }
          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Error Occured While Deleting Auth Resource",
              error_detail: error
            } );

          }
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating P.A.T Token in Delete Resource",
          error_detail: error
        } );
      }
    } );
  }

  //Get User Based Policy.
  async getPolicy( policyName, token, clientId ) {

    return new Promise( async ( resolve, reject ) => {


      let URL = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig[ "realm" ] + "/clients/" + clientId + "/authz/resource-server/policy?name=" + policyName + "&exact=true";

      var config = {

        method: "get",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        headers: {
          Authorization: "Bearer " + token,
        },

      };

      try {

        let result = await requestController.httpRequest( config, false );
        let policy = result.data[ 0 ];

        resolve( policy );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Fetching Policy For Team Supervisor Assignment During Finesse User Creation.",
          error_detail: error
        } );
      }



    } );

  }

  createPolicy( policyName, roles ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token";

      var config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          username: keycloakConfig.USERNAME_ADMIN,
          password: keycloakConfig.PASSWORD_ADMIN,
          grant_type: keycloakConfig.GRANT_TYPE,
          client_secret: keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        //   T.O.K.E.N    R.E.Q.U.E.S.T  (user with admin is already defined in keycloak with roles 'realm-management')
        //   //  C.R.E.A.T.E    U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y
        let URL3 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/clients/" + keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/role";
        config.url = URL3;
        config.headers[ "Content-Type" ] = "application/json";
        config.headers.Authorization = "Bearer " + token;

        config.data.decisionStrategy = "AFFIRMATIVE";
        config.data.logic = "POSITIVE";
        config.data.name = policyName;
        config.data.type = "role";
        config.data.id = policyName;
        config.data.roles = roles;

        delete config.data[ "client_id" ];
        delete config.data[ "client_secret" ];
        delete config.data[ "grant_type" ];
        delete config.data[ "username" ];
        delete config.data[ "password" ];
        config.data = JSON.stringify( config.data );

        try {

          let policyResponse = await requestController.httpRequest( config, false );
          resolve( policyResponse );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured While Creating Role Based Policy",
            error_detail: error
          } );
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating Admin Token During Creation OF Policy",
          error_detail: error
        } );
      }
    } );
  }

  //Update User Based Policy.
  async updateUserBasedPolicy( policyObj, token, clientId ) {

    return new Promise( async ( resolve, reject ) => {


      let policyId = policyObj.id;
      let URL = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig[ "realm" ] + "/clients/" + clientId + "/authz/resource-server/policy/user/" + policyId;

      delete policyObj.id;

      var config = {

        method: "put",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        headers: {
          Authorization: "Bearer " + token,
        },
        data: policyObj,

      };

      try {

        let result = await requestController.httpRequest( config, false );
        let updatedPolicy = result.data;

        resolve( updatedPolicy );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Updating User-Based Policy During Finesse User Creation.",
          error_detail: error
        } );

      }

    } );
  }

  createPermission( resourceName, policyName, permissionName, scopeName ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token";

      var config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          username: keycloakConfig.USERNAME_ADMIN,
          password: keycloakConfig.PASSWORD_ADMIN,
          grant_type: keycloakConfig.GRANT_TYPE,
          client_secret: keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        //   T.O.K.E.N    R.E.Q.U.E.S.T  (user with admin is already defined in keycloak with roles 'realm-management')
        //   //  C.R.E.A.T.E    U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y
        let URL3 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/clients/" + keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/permission/scope";
        config.url = URL3;
        config.headers[ "Content-Type" ] = "application/json";
        config.headers.Authorization = "Bearer " + token;

        config.data.decisionStrategy = "AFFIRMATIVE";
        config.data.logic = "POSITIVE";
        config.data.name = permissionName;
        config.data.policies = policyName;
        config.data.resources = resourceName;
        config.data.scopes = scopeName;
        config.data.type = "scope";
        config.data.id = permissionName;

        delete config.data[ "client_id" ];
        delete config.data[ "client_secret" ];
        delete config.data[ "grant_type" ];
        delete config.data[ "username" ];
        delete config.data[ "password" ];
        config.data = JSON.stringify( config.data );

        try {

          let policyResponse = await requestController.httpRequest( config, false );
          resolve( policyResponse );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured During Creation Of Auth Permission.",
            error_detail: error
          } );

        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating Admin Token During Creation Of Permission.",
          error_detail: error
        } );
      }
    } );
  }

  //   R.E.S.O.U.R.C.E    A.U.T.H.O.R.I.Z.A.T.I.O.N        (    E.V.A.L.U.A.T.E    U.S.E.R    T.O   A    R.E.S.O.U.R.C.E   )
  resourceAuthorization( keycloak_user_id, resource_name ) {

    return new Promise( async ( resolve, reject ) => {

      let token;

      var config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          username: keycloakConfig.USERNAME_ADMIN,
          password: keycloakConfig.PASSWORD_ADMIN,
          grant_type: keycloakConfig.GRANT_TYPE,
          client_secret: keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        // EVALUATION REQUEST
        var data = JSON.stringify( {
          resources: [ { _id: resource_name } ],
          clientId: keycloakConfig.CLIENT_DB_ID,
          userId: keycloak_user_id,
        } );

        config.data.clientId = keycloakConfig.CLIENT_DB_ID;
        config.data.resources = [ { _id: resource_name } ];
        config.data.userId = keycloak_user_id;
        delete config.data[ "username" ];
        delete config.data[ "password" ];
        delete config.data[ "grant_type" ];
        delete config.data[ "client_secret" ];
        delete config.data[ "client_id" ];

        let URL5 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/clients/" + keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/evaluate";
        config.url = URL5;
        config.headers[ "Content-Type" ] = "application/json";
        ( config.headers.Authorization = "Bearer " + token ), ( config.data = JSON.stringify( config.data ) );

        try {

          let evaluationResponse = await requestController.httpRequest( config, false );
          resolve( evaluationResponse );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured During Auth Evaluation Process.",
            error_detail: error
          } );
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating Admin Token During Resource Evaluation Process.",
          error_detail: error
        } );
      }
    } );
  }

  revokeUseronResource( resource_name, keycloak_user_id ) {

    return new Promise( async ( resolve, reject ) => {

      let token;

      var config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          username: keycloakConfig.USERNAME_ADMIN,
          password: keycloakConfig.PASSWORD_ADMIN,
          grant_type: keycloakConfig.GRANT_TYPE,
          client_secret: keycloakConfig.credentials.secret,
        },
      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;
        // now deleting policy
        config.method = "delete";
        delete config.data;
        let URL6 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/clients/" + keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/user/" + resource_name + "-policy";
        config.url = URL6;
        delete config.headers[ "Accept" ];
        delete config.headers[ "cache-control" ];
        delete config.headers[ "Content-Type" ];
        config.headers.Authorization = "Bearer " + token;

        try {

          let deletePolicy = await requestController.httpRequest( config, false );
          resolve( deletePolicy );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured While Deletion Of Policy.",
            error_detail: error
          } );
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating Admin Token During Deletion Of Policy.",
          error_detail: error
        } );
      }

    } );
  }


  async getUserSupervisedGroups( userId, username, roles, adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let team = {};
      let error;

      var config = {

        method: "get",
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        }

      };

      try {

        //User Groups
        let URL = keycloakConfig[ "ef-server-url" ] + "team/user/" + userId;
        config.url = URL;

        try {

          let userTeams = await requestController.httpRequest( config, true );

          const { userTeam, supervisedTeams } = userTeams.data;

          if ( Object.keys( userTeam ).length == 0 ) {

            reject( {
              error_message: "Error Occured While Fetching User Team.",
              error_detail: {
                status: 403,
                reason: "No Teams group assigned to User, please assign a Team to user. If user has no team then assign it default group."
              }
            } );

          }

          let supervisedTeamsFiltered = [];
          let secondarySupervisedTeamsFiltered = [];

          if ( supervisedTeams.length > 0 ) {

            // Filter teams where the user is the primary supervisor
            supervisedTeamsFiltered = supervisedTeams.filter( team => team.supervisor.toLocaleLowerCase() === username.toLocaleLowerCase() )
              .map( team => {
                return { teamId: team.teamId, teamName: team.teamName };
              } );

            // Filter teams where the user is a secondary supervisor
            secondarySupervisedTeamsFiltered = supervisedTeams.filter( team => team.secondarySupervisors.some( sup => sup.username.toLocaleLowerCase() === username.toLocaleLowerCase() ) )
              .map( team => {
                return { teamId: team.teamId, teamName: team.teamName };
              } );
          }


          //User Groups
          let URL1 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/users/" + userId + "/groups";
          config.url = URL1;
          config.headers.Authorization = "Bearer " + adminToken;

          try {

            let userGroup = await requestController.httpRequest( config, true );

            if ( userGroup.data.length != 0 ) {

              let groups = userGroup.data;
              let permissionGroups = groups.filter( ( group ) => group.name.includes( "_permission" ) );

              if ( permissionGroups.length > 0 ) {

                team.permissionGroups = [];

                permissionGroups.forEach( perGroup => {

                  team.permissionGroups.push( perGroup.name );
                } );
              }
            }

          } catch ( er ) {

            error = await errorService.handleError( er );

            reject( {
              error_message: "Error Occured While Fetching User Team.",
              error_detail: error
            } );

          }

          team.userTeam = userTeam;
          team.supervisedTeams = supervisedTeamsFiltered;
          team.secondarySupervisedTeams = secondarySupervisedTeamsFiltered;

          resolve( team );

        } catch ( er ) {

          error = await errorService.handleError( er );

          reject( {
            error_message: "Error Occured While Fetching User Team.",
            error_detail: error
          } );

        }

      } catch ( er ) {

        error = await errorService.handleError( er );

        reject( {
          error_message: "Error Occured While Generating Admin Access Token To Fetch User Team and User Supervised Teams.",
          error_detail: error
        } );

      }

    } );
  }

  //function to be used only in teams implementation
  async getTeamUsers( keycloakObj, groupsIdsArr, userToken ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let message;
      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token";



      if ( typeof keycloakObj == "object" && Object.keys( keycloakObj ).length != 0 && Array.isArray( groupsIdsArr ) && userToken.length > 0 ) {

        //Validate whether user in keycloakObj is same as user in userToken.
        const parseJwt = ( userToken ) => {

          try {

            return JSON.parse( Buffer.from( userToken.split( "." )[ 1 ], "base64" ).toString() );
          } catch ( er ) {

            return null;
          }

        };

        let verifyToken = parseJwt( userToken );

        if ( keycloakObj.username != verifyToken.preferred_username ) {

          message = `The data provided in Keycloak Object as an Argument doesn't belong to current Logged-In user.`;

          resolve( {

            status: 401,
            message: message,

          } );

        }

        var config = {

          method: "post",
          url: URL,
          headers: {
            Accept: "application/json",
            "cache-control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          data: {
            client_id: keycloakConfig.CLIENT_ID,
            username: keycloakConfig.USERNAME_ADMIN,
            password: keycloakConfig.PASSWORD_ADMIN,
            grant_type: keycloakConfig.GRANT_TYPE,
            client_secret: keycloakConfig.credentials.secret,
          },

        };

        try {

          let adminTokenResponse = await requestController.httpRequest( config, true );
          token = adminTokenResponse.data.access_token;

          let allUsers = [];
          let groupsData;

          config.method = "get";
          delete config.data;
          delete config.url;
          config.headers.Authorization = "Bearer " + token;

          let clientRoles = await this.getUserInfoFromToken( keycloakObj.username, userToken );

          if ( clientRoles.status ) {

            resolve( clientRoles );
          }

          //admin case
          if ( "realm-management" in clientRoles ) {

            let URL2 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/groups";
            config.url = URL2;

            try {

              let groups = await requestController.httpRequest( config, true );
              delete config.url;

              groupsData = groups.data;
              groupsData = groupsData.filter( ( group ) => !group.name.includes( "_permission" ) );

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Error Occured While Fetching Groups In Team Users List Component.",
                error_detail: error
              } );
            }

          } else {

            //agent case
            if ( keycloakObj.supervisedTeams.length == 0 ) {
              resolve( [] );

              //supervisor case
            } else {

              //if no group ids are provided, send all the users of groups this user supervises.
              if ( groupsIdsArr.length == 0 ) {

                let supervisedGroups = keycloakObj.supervisedTeams;
                supervisedGroups = supervisedGroups.filter( ( group ) => !group.teamName.includes( "_permission" ) );
                groupsData = supervisedGroups;

                //only send the users of provided groups.
              } else {

                let groupsArr = [];
                let idsArr = groupsIdsArr;

                idsArr.forEach( ( id ) => {

                  let group = keycloakObj.supervisedTeams.find( ( group ) => {
                    return group.teamId == id;
                  } );

                  if ( !group ) {

                    message = `Given User doesn't suprvise any group against id: ${id}`;

                    resolve( {
                      status: 404,
                      message: message,
                    } );

                  }

                  groupsArr.push( group );

                } );

                groupsArr = groupsArr.filter( ( group ) => !group.teamName.includes( "_permission" ) );
                groupsData = groupsArr;

              }
            }
          }

          allUsers = await teamsService.getUsersOfGroups( groupsData, config, keycloakConfig );
          resolve( allUsers );

        } catch ( er ) {


          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured While Generating Admin Token During Fetching Of Team Users.",
            error_detail: error
          } );

        }
      }

      message = "Please pass the valid arguments. First argument must be  (should not be empty object," +
        "must contain valid key-value pair) and Second argument must be Array of groupIds (could be an empty array)" +
        "3rd Argument must be valid Access Token of current logged-in user.";

      resolve( {

        status: 400,
        message: message,
      } );

    } );
  }

  //function to be used only in teams implementation. We give the list of ids of groups and it returns all its members and supervisors
  async getGroupMembers( groupIds ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let groupsData = [];
      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token";

      var config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          username: keycloakConfig.USERNAME_ADMIN,
          password: keycloakConfig.PASSWORD_ADMIN,
          grant_type: keycloakConfig.GRANT_TYPE,
          client_secret: keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        if ( groupIds.length > 0 ) {

          config.method = "get";
          delete config.data;
          delete config.url;
          config.headers.Authorization = "Bearer " + token;

          for ( let i = 0; i < groupIds.length; i++ ) {

            try {

              let groupData = {};

              let URL2 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/groups/" + groupIds[ i ] + "/";
              config.url = URL2;
              let groupInfo = await requestController.httpRequest( config, true );

              groupData.teamId = groupInfo.data.id;
              groupData.teamName = groupInfo.data.name;

              if ( Object.keys( groupInfo.data.attributes ).length == 0 ) {

                groupData.supervisors = [];
              } else {

                let attributes = groupInfo.data.attributes;

                if ( "supervisor" in attributes ) {

                  let supervisorList = attributes[ "supervisor" ][ 0 ].split( "," );
                  let supervisors = [];

                  for ( let j = 0; j < supervisorList.length; j++ ) {

                    let URL3 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/users?username=" + supervisorList[ j ] + "&exact=true";
                    config.url = URL3;

                    try {

                      let supervisorUser = await requestController.httpRequest( config, true );

                      if ( supervisorUser.data.length > 0 ) {

                        supervisors.push( {
                          supervisorId: supervisorUser.data[ 0 ].id,
                          supervisorName: supervisorUser.data[ 0 ].username,
                        } );
                      }

                    } catch ( er ) {

                      let error = await errorService.handleError( er );

                      reject( {

                        error_message: "Error Occured While Fetching Supervisor Users In Team Members List Component.",
                        error_detail: error
                      } );
                    }
                  }

                  groupData.supervisors = supervisors;
                }
              }

              let URL4 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/groups/" + groupIds[ i ] + "/members";
              config.url = URL4;
              let users = await requestController.httpRequest( config, true );

              if ( users.data.length > 0 ) {

                let agents = users.data;
                agents = agents.map( ( agent ) => {

                  return {
                    agentId: agent.id,
                    agentName: agent.username,
                  };
                } );

                groupData.agents = agents;

              } else {

                groupData.agents = [];
              }

              groupsData.push( groupData );

            } catch ( err ) {

              if ( err.response && err.response.status !== 404 ) {

                let error = await errorService.handleError( err );

                reject( {

                  error_message: "Error Occured While Fetching Teams Against TeamIds In Team Members List Component.",
                  error_detail: error
                } );

              } else if ( err.message ) {

                if ( err.message !== "Request failed with status code 404" ) {

                  let error = await errorService.handleError( err );

                  reject( {

                    error_message: "Error Occured While Fetching Teams Against TeamIds In Team Members List Component.",
                    error_detail: error
                  } );
                }

              } else {

                continue;
              }
            }
          }

          resolve( groupsData );
        }

        resolve( [] );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating Admin Token In Team Members List Component.",
          error_detail: error
        } );

      }

    } );
  }

  // this function requires comma separated list of roles in parameter e.g ["robot","human","customer"];
  getUsersByRole( keycloak_roles ) {

    return new Promise( async ( resolve, reject ) => {

      let token;


      try {

        //Fetching admin token, we pass it in our "Create User" API for authorization
        let keycloakAuthToken = await this.getAccessToken( keycloakConfig[ "USERNAME_ADMIN" ], keycloakConfig[ "PASSWORD_ADMIN" ] );

        if ( keycloakAuthToken.access_token ) {

          token = keycloakAuthToken.access_token;

          let config = {
            method: "get",
            headers: {
              Accept: "application/json",
              "cache-control": "no-cache",
              "Content-Type": "application/x-www-form-urlencoded",
              Authorization: `Bearer ${token}`
            }
          };

          let userObject = {}; // to read data object having all users of a certain role
          let count = 0;
          let flag = true;
          let obj = []; // final object to be returned

          for ( let i = 0; i < keycloak_roles.length; i++ ) {

            try {

              config.url = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig.realm + "/roles/" + keycloak_roles[ i ] + "/users?max=100000";
              let getUsersfromRoles = await requestController.httpRequest( config, true );
              userObject = getUsersfromRoles.data;

              userObject.forEach( ( user ) => {

                if ( count > 0 ) {

                  let userIndex = obj.findIndex( ( usr ) => {
                    return usr.username == user.username;
                  } );

                  if ( userIndex != -1 ) {
                    obj[ userIndex ].roles.push( keycloak_roles[ i ] );
                    flag = false;
                  }

                }

                if ( flag == true ) {

                  obj.push( {
                    id: user.id,
                    username: user.username,
                    firstName: user.firstName == undefined ? "" : user.firstName,
                    lastName: user.lastName == undefined ? "" : user.lastName,
                    roles: [ keycloak_roles[ i ] ],
                  } );

                }

                flag = true;
              } );

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Error Occured While Fetching Users Against Roles In Get Users By Role Component.",
                error_detail: error
              } );
            }

            count++;
          }

          resolve( obj );
        }

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Generating Admin Token In Get Users By Role Component.",
          error_detail: error
        } );
      }
    } );
  }

  async getRealmRoles( adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/roles`;

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

          error_message: "Error Occured While Fetching Realm Roles.",
          error_detail: error
        } );

      }
    } );
  }

  async assignRoleToUser( userId, roles, adminToken ) {

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

          error_message: "Error Occured While Assigning Role To User.",
          error_detail: error
        } );
      }
    } );
  }

  async getKeycloakUserGroups( userId, adminToken ) {

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

          error_message: "Error Occured While Fetching Groups of User using UsedId.",
          error_detail: error
        } );
      }
    } );

  }

  async gettingGroupByGroupName( groupNames, adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let groups = [];


      for ( let name of groupNames ) {

        let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/groups?search=${name}`;

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
          let exactGroup;

          if ( tokenResponse.data.length > 1 ) {
            exactGroup = tokenResponse.data.find( group => group.name == name );

            groups.push( {
              id: exactGroup.id,
              name: exactGroup.name
            } );

          } else {

            groups.push( {
              id: tokenResponse.data[ 0 ].id,
              name: tokenResponse.data[ 0 ].name
            } );
          }

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured While Fetching Groups using GroupName.",
            error_detail: error
          } );
        }

      }

      resolve( groups );

    } );

  }

  async getGroupById( groupId, adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/groups/${groupId}/`;

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
        let group = tokenResponse.data;
        resolve( group );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Fetching Group using GroupId.",
          error_detail: error
        } );
      }

    } );
  }

  async addOrRemoveUserGroup( userId, groups, operation, adminToken ) {


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

        let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users/${userId}/groups/${group.id}`;
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

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured While Adding/Removing Roles of User using UsedId.",
            error_detail: error
          } );

        }

      }

      resolve( [] );

    } );

  }

  async addOrRemoveUserRole( userId, roles, operation, token ) {

    return new Promise( async ( resolve, reject ) => {

      let method = ( operation == 'remove' ) ? 'delete' : 'post';

      if ( realmRoles.length > 0 ) {

        let check = checkForMissingRole( realmRoles, roles );

        if ( !check ) {

          realmRoles = await this.getRealmRoles( token );
        }

      } else {

        realmRoles = await this.getRealmRoles( token );
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

          error_message: "Error Occured While Adding/Removing Roles of User using UsedId.",
          error_detail: error
        } );
      }
    } );
  }

  async createGroup( adminToken, groupName ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/groups`;

      let data = {
        name: groupName,
      };

      let config = {
        method: "post",
        url: URL,
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
        data: data,
      };

      try {

        let createdGroup = await requestController.httpRequest( config, false );
        resolve( createdGroup.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Creation Of Group In Create Group Component.",
          error_detail: error
        } );
      }

    } );
  }

  //Authenticating Finesse User
  async authenticateFinesse( username, password, finesseUrl, userRoles, finesseToken ) {

    return new Promise( async ( resolve, reject ) => {

      //Authentication of Finesse User, it returns a status code 200 if user found and 401 if unauthorized.
      let finesseLoginResponse;

      try {
        //Handle finesse error cases correctly. (for later)
        if ( finesseToken.length == 0 ) {

          finesseLoginResponse = await finesseService.authenticateUserViaFinesse( username, password, finesseUrl );

        } else {


          finesseLoginResponse = await finesseService.authenticateUserViaFinesseSSO( username, finesseToken, finesseUrl );
        }

        //If user is SSO then password is not provided, we are setting up a pre-defined password.
        password = password.length == 0 ? "123456" : password;
        finesseLoginResponse.data.password = password;

        let authenticatedByKeycloak = false;
        let keycloakAuthToken = null;
        let keycloakAdminToken = null;
        let updateUserPromise = null;

        if ( finesseLoginResponse.status == 200 ) {

          try {

            //Fetching admin token, we pass it in our "Create User" API for authorization
            keycloakAdminToken = await this.getAccessToken( keycloakConfig[ "USERNAME_ADMIN" ], keycloakConfig[ "PASSWORD_ADMIN" ] );

            try {

              //Checking whether finesse password is updated or not. If updated, update it on keycloak as well without halting login process
              await this.checkPasswordUpdate( keycloakAdminToken.access_token, finesseLoginResponse.data.username, password );
              //Checking whether finesse user already exist in keycloak and fetch its token
              keycloakAuthToken = await this.getAccessToken( finesseLoginResponse.data.username, password, keycloakConfig[ "realm" ] );
              authenticatedByKeycloak = true;

              if ( !updateUserPromise ) {

                updateUserPromise = this.updateUser( finesseLoginResponse.data, keycloakAdminToken, keycloakAuthToken, finesseLoginResponse.data.username, password )
                  .then( async ( updatedUser ) => {

                    //Calling the Introspect function twice so all the asynchronous operations inside updateUser function are done
                    keycloakAuthToken = await this.getKeycloakTokenWithIntrospect( finesseLoginResponse.data.username, password, keycloakConfig[ "realm" ] );
                  } )
                  .catch( ( err ) => {

                    reject( err );
                  } );
              }


            } catch ( err ) {

              if ( err.error_detail ) {

                if ( err.error_detail.status == 401 ) {

                  console.log( "User doesn't exist in Keycloak, syncing finesse user in keycloak..." );
                } else {

                  reject( err );
                }
              } else {

                reject( err );
              }

            }
          } catch ( err ) {

            let error = await errorService.handleError( err );

            reject( {

              error_message: "Error While Fetching Keycloak Admin Token In Authenticate/Sync Finesse User Component.",
              error_detail: error
            } );


          } finally {

            //Finesse User not found in keycloak, so we are going to create one.
            if ( !authenticatedByKeycloak ) {

              if ( keycloakAdminToken.access_token ) {

                let token = keycloakAdminToken.access_token;

                //validating customer Before Creation
                let { error, value } = validateUser( {
                  username,
                  password,
                  token,
                  userRoles,
                } );

                if ( error ) {

                  reject( {
                    status: 400,
                    message: "Error while creation of user, error message: " + error.details[ 0 ].message,
                  } );
                }
              }

              try {

                //Creating Finesse User inside keycloak.
                let userCreated = await this.createUser( finesseLoginResponse.data, keycloakAdminToken.access_token );

                if ( userCreated.status == 201 ) {

                  //Returning the token of recently created User
                  keycloakAuthToken = await this.getKeycloakTokenWithIntrospect( ( finesseLoginResponse.data.username ).toLowerCase(), password, keycloakConfig[ "realm" ] );
                }

              } catch ( err ) {


                let error = await errorService.handleError( err );

                reject( {

                  error_message: "Error While Creation Of Finesse User In Authenticate/Sync Finesse User Component.",
                  error_detail: error
                } );

              }
            }
          }

          if ( updateUserPromise ) {
            await updateUserPromise; // Wait for the updateUser promise to resolve
            updateUserPromise = null; // Reset the promise
          }

          resolve( keycloakAuthToken );
        } else {

          resolve( finesseLoginResponse );
        }
      } catch ( er ) {

        reject( er );
      }
    } );
  }

  //Create a Finesse user during login.
  async createUser( userObject, token ) {

    let assignRole = [];
    let assignGroups = [];

    assignGroups = userObject.roles.includes( "supervisor" ) ? [ "agents_permission", "senior_agents_permission" ] : [ "agents_permission" ];


    return new Promise( async ( resolve, reject ) => {

      let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users`;

      let data = {

        username: userObject.username,
        firstName: userObject.firstName,
        lastName: userObject.lastName,
        enabled: true,
        credentials: [
          {
            type: "password",
            value: userObject.password,
            temporary: false,
          },
        ],
        attributes: {
          "user_name": `${userObject.loginName}`,
          "extension": `${userObject.extension}`
        },
        groups: assignGroups
      };

      let config = {

        method: "post",
        url: URL,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
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
        if ( userObject.roles != [] ) {

          if ( realmRoles.length > 0 ) {

            let check = checkForMissingRole( realmRoles, userObject.roles );

            if ( !check ) {

              realmRoles = await this.getRealmRoles( token );
            }

          } else {

            realmRoles = await this.getRealmRoles( token );
          }

          //checking whether role exist in realmRoles object array:
          for ( let role of realmRoles ) {

            userObject.roles.forEach( ( userRole ) => {

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
            let roleAssigned = await this.assignRoleToUser( userId, assignRole, token );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Error Occured While Assignment of Role To User In Finesse User Creation Component.",
              error_detail: error
            } );
          }
        }


        let ciscoTeamId = userObject.group.id;

        //Check whether team of Agent already exists in CX Core or not
        let URL1 = `${keycloakConfig[ "ef-server-url" ]}team?ids=${ciscoTeamId}`;

        let config1 = {

          url: URL1,
          method: "get",
          headers: {
            Accept: "application/json",
            "cache-control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
          }

        };

        let config2 = {

          method: "post",
          headers: {
            Accept: "application/json",
            "cache-control": "no-cache",
            "Content-Type": "application/json",
          },

        };


        try {

          let getAgentCXTeam = await requestController.httpRequest( config1, false );

          let createAgentCXTeam;

          //This means the team doesn't exist in CX Core. We need to create a team
          if ( getAgentCXTeam.data.length == 0 ) {

            //Setting URL to Create CX team of Agent
            let URL2 = `${keycloakConfig[ "ef-server-url" ]}team`;

            let data = {
              "team_Id": userObject.group.id,
              "team_name": userObject.group.name,
              "supervisor_Id": "",
              "source": "CISCO",
              "created_by": "1"
            }

            config2.url = URL2;
            config2.data = data;

            try {

              //Creating CX team of Agent
              createAgentCXTeam = await requestController.httpRequest( config2, false );

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Error Occured While Creating CX Core Team.",
                error_detail: error
              } );
            }

          }

          //First send the newly created user to CX DB.
          let URL3 = `${keycloakConfig[ "ef-server-url" ]}users/`;

          let data = {
            "id": userId,
            "username": userObject.username.toLocaleLowerCase(),
            "firstName": userObject.firstName,
            "lastName": userObject.lastName,
            "roles": userObject.roles
          }

          config2.url = URL3;
          config2.data = data;

          try {

            let sendSupUserToCX = await requestController.httpRequest( config2, false );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Error Occured While Sending User Details to CX.",
              error_detail: error
            } );
          }

          //Assign Agent to a team
          let URL4 = `${keycloakConfig[ "ef-server-url" ]}team/${userObject.group.id}/member`;

          data = {
            "type": "agent",
            "usernames": [ userObject.username.toLocaleLowerCase() ]
          }

          config2.url = URL4;
          config2.data = data;

          try {

            //Assigning Agent to CX team
            let assignAgentToTeam = await requestController.httpRequest( config2, false );
            console.log( assignAgentToTeam.data );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Error Occured While Assigning Agent to CX Core Team.",
              error_detail: error
            } );
          }

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Error Occured While Fetching CX Core Team.",
            error_detail: error
          } );
        }



        if ( userObject.roles.includes( "supervisor" ) && userObject.supervisedGroups.length > 0 ) {


          for ( let supervisedGroup of userObject.supervisedGroups ) {

            let supervisorTeamId = supervisedGroup.id;

            //Check whether team of Supervisor already exists in CX Core or not
            let URL5 = `${keycloakConfig[ "ef-server-url" ]}team?ids=${supervisorTeamId}`;

            config1.url = URL5;

            try {

              let getSupervisorCXTeam = await requestController.httpRequest( config1, false );

              //This means the team doesn't exist in CX Core. We need to create a team
              if ( getSupervisorCXTeam.data.length == 0 ) {

                //Creating or Updating Supervisor team in CX Core.
                let URL6 = `${keycloakConfig[ "ef-server-url" ]}team`;

                let data = {
                  "team_Id": supervisorTeamId,
                  "team_name": supervisedGroup.name,
                  "supervisor_Id": userId,
                  "source": "CISCO",
                  "created_by": "1"
                }

                config2.method = 'post';
                config2.url = URL6;
                config2.data = data;

                try {

                  //Creating CX team of Supervisor
                  let createSupervisorCXTeam = await requestController.httpRequest( config2, false );

                } catch ( er ) {

                  let error = await errorService.handleError( er );

                  reject( {

                    error_message: "Error Occured While Creating CX Core Team.",
                    error_detail: error
                  } );
                }

              } else {

                //Check whether team of Supervisor already exists in CX Core or not
                let URL7 = `${keycloakConfig[ "ef-server-url" ]}team/${supervisorTeamId}`;

                let data = {
                  "team_name": getSupervisorCXTeam.data[ 0 ].team_name,
                  "supervisor_Id": userId
                }

                config2.method = 'put';
                config2.url = URL7;
                config2.data = data;


                try {

                  //Updating CX team of Supervisor
                  let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                } catch ( er ) {

                  let error = await errorService.handleError( er );

                  reject( {

                    error_message: "Error Occured While Updating CX Core Team.",
                    error_detail: error
                  } );
                }

              }


            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Error Occured While Fetching CX Core Team.",
                error_detail: error
              } );
            }
          }

          resolve( newUser );

        } else {

          resolve( newUser );
        }

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Creation Of User In Finesse User Creation Component.",
          error_detail: error
        } );
      }
    } );
  }

  //Check for changes in Finesse User on Each login.
  async updateUser( finObj, keycloakAdminToken, keycloakAuthToken, username, password ) {
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
      let userAttributes;

      let rolesToAdd;
      let rolesToRemove;
      let groupsToAdd;
      let groupsToRemove;
      let keycloakGroups;


      try {

        let rptToken = await this.getTokenRPT( username, password, keycloakAuthToken.access_token );
        let introspectToken = await this.getIntrospectToken( rptToken.access_token );

        let keyObj = {
          id: introspectToken.sub,
          username: introspectToken.username,
          firstName: introspectToken.given_name,
          lastName: introspectToken.family_name,
          roles: introspectToken.realm_access.roles,
          permittedResources: {
            Resources: introspectToken.authorization.permissions,
          }
        }

        //get user attributes to check its user_name and extension
        let URL = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users/${keyObj.id}`;

        let config = {

          method: "get",
          url: URL,
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${keycloakAdminToken.access_token}`,
          }
        };

        try {

          let userDataResponse = await requestController.httpRequest( config, false );
          userAttributes = userDataResponse.data.attributes;

        } catch ( err ) {

          let error = await errorService.handleError( err );

          reject( {

            error_message: "Error Occured While Fetching User Data during Cisco User Sync Update Process.",
            error_detail: error
          } );

        }

        //Comparing the basic info of Finesse User and Normal User.
        if ( ( finObj.username ).toLowerCase() != keyObj.username
          || finObj.firstName != keyObj.firstName
          || finObj.lastName != keyObj.lastName
          || ( userAttributes.user_name && finObj.loginName !== userAttributes.user_name[ 0 ] )
          || ( userAttributes.extension && finObj.extension !== userAttributes.extension[ 0 ] )
          || ( !userAttributes.user_name )
        ) {

          data = {
            username: ( finObj.username ).toLowerCase(),
            firstName: finObj.firstName,
            lastName: finObj.lastName,
            attributes: {
              "user_name": `${finObj.loginName}`,
              "extension": `${finObj.extension}`
            }
          };
        }

        if ( Object.keys( data ).length > 0 ) {


          let URL1 = `${keycloakConfig[ "auth-server-url" ]}${keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${keycloakConfig[ "realm" ]}/users/${keyObj.id}`;

          config.url = URL1;
          config.method = 'put';
          config.data = data;

          try {

            await requestController.httpRequest( config, false );


          } catch ( err ) {

            let error = await errorService.handleError( err );

            reject( {

              error_message: "Error Occured While Updating User Info during Cisco User Sync Process.",
              error_detail: error
            } );

          }

        }


        //Role to Add to keycloak user during Update process.
        //rolesToAdd = finObj.roles.filter( role => !keyObj.roles.includes( role ) );
        rolesToAdd = finObj.roles;

        //Role to Remove from keycloak user during Update process.
        let ignoreRoles = [ 'offline_access', 'uma_authorization' ];
        rolesToRemove = keyObj.roles.filter( role => (
          !finObj.roles.includes( role ) &&
          !ignoreRoles.includes( role ) &&
          role.indexOf( "default-roles" ) == -1 ) );

        //Updating group data in case it is not similar.
        let finesseGroups = finObj.roles.includes( "supervisor" ) ? [ "agents_permission", "senior_agents_permission" ] : [ "agents_permission" ];

        try {

          let token = keycloakAdminToken.access_token;

          let userGroups = await this.getKeycloakUserGroups( keyObj.id, token );

          keycloakGroups = userGroups.map( group => {
            return {
              id: group.id,
              name: group.name
            }
          } );

          //find if senior_agents_permission group is assigned to user already against an agent role.
          let isSeniorAgent = keycloakGroups.some( group => group.name == 'senior_agents_permission' );

          if ( isSeniorAgent && keyObj.roles.includes( 'agent' ) && !finesseGroups.includes( 'senior_agents_permission' ) ) {
            finesseGroups.push( 'senior_agents_permission' );
          }

          groupsToAdd = finesseGroups.filter( group => !keycloakGroups.find( keygroup => keygroup.name == group ) );
          groupsToRemove = keycloakGroups.filter( group => !finesseGroups.includes( group.name ) );

          //Adding and Removing Roles from Keycloak
          try {

            if ( rolesToAdd.length > 0 || rolesToRemove.length > 0 ) {
              const rolesPromises = [];

              if ( rolesToAdd.length > 0 ) {
                let addRolesPromise = this.addOrRemoveUserRole( keyObj.id, rolesToAdd, 'add', token );
                rolesPromises.push( addRolesPromise );
              }

              if ( rolesToRemove.length > 0 ) {
                let removeRolesPromise = this.addOrRemoveUserRole( keyObj.id, rolesToRemove, 'remove', token );
                rolesPromises.push( removeRolesPromise );
              }

              /* if ( rolesToAdd.includes( "supervisor" ) ) {

                keycloakAuthToken = await this.getAccessToken( keyObj.username, password, keycloakConfig[ "realm" ] );
                rptToken = await this.getTokenRPT( keyObj.username, password, keycloakAuthToken.access_token );
                introspectToken = await this.getIntrospectToken( rptToken.access_token );
                keyObj.permittedResources.Resources = introspectToken.authorization.permissions;
              } */

              // Wait for all promises to complete before moving on
              await Promise.all( rolesPromises );
            }

            try {


              if ( groupsToAdd.length > 0 ) {

                //Fetching Ids of all the groups to add to current Keycloak User.
                groupsToAdd = await this.gettingGroupByGroupName( groupsToAdd, token );
                await this.addOrRemoveUserGroup( keyObj.id, groupsToAdd, 'add', token );
              }

              if ( groupsToRemove.length > 0 ) {

                await this.addOrRemoveUserGroup( keyObj.id, groupsToRemove, 'remove', token );
              }

              //Checking Agent Case first, if agent team in CX is not same as agent team in finesse then update it
              let userId = keyObj.id;
              let config1 = {

                method: "get",
                headers: {
                  Accept: "application/json",
                  "cache-control": "no-cache",
                  "Content-Type": "application/x-www-form-urlencoded",
                }

              };

              //User Groups
              let URL2 = keycloakConfig[ "ef-server-url" ] + "team/user/" + userId;
              config1.url = URL2;

              let config2 = {

                method: "post",
                headers: {
                  Accept: "application/json",
                  "cache-control": "no-cache",
                  "Content-Type": "application/json",
                },

              };

              try {

                let userTeams = await requestController.httpRequest( config1, true );

                const { userTeam, supervisedTeams } = userTeams.data;

                let supervisedTeamsFiltered = [];

                if ( supervisedTeams.length > 0 ) {

                  // Filter teams where the user is the primary supervisor
                  supervisedTeamsFiltered = supervisedTeams.filter( team => team.supervisor.toLocaleLowerCase() === username.toLocaleLowerCase() )
                    .map( team => {
                      return { teamId: team.teamId, teamName: team.teamName };
                    } );
                }

                //If Agent team in finesse is different from Agent Team in finesse
                if ( finObj.group.id !== userTeam.teamId ) {

                  //We have to both add agent to a team corresponding to Finesse and remove it from CX team.
                  //Removing agent from CX team first
                  let URL3 = `${keycloakConfig[ "ef-server-url" ]}team/${userTeam.teamId}/member?type=agent&usernames=${finObj.username.toLowerCase()}`;

                  config1.method = 'delete';
                  config1.url = URL3;

                  try {

                    let removeAgentFromCXTeam = await requestController.httpRequest( config1, true );

                  } catch ( er ) {

                    let error = await errorService.handleError( er );

                    reject( {
                      error_message: "Error Occurred while Deleting User from a team In Finesse User Login (Update).",
                      error_detail: error
                    } );

                  }

                  //Check whether team of Agent already exists in CX Core or not
                  let URL4 = `${keycloakConfig[ "ef-server-url" ]}team?ids=${finObj.group.id}`;

                  config1.method = 'get';
                  config1.url = URL4;


                  try {

                    let getAgentCXTeam = await requestController.httpRequest( config1, false );

                    let createAgentCXTeam;

                    //This means the team doesn't exist in CX Core. We need to create a team
                    if ( getAgentCXTeam.data.length == 0 ) {

                      //Setting URL to Create CX team of Agent
                      let URL5 = `${keycloakConfig[ "ef-server-url" ]}team`;

                      let data = {
                        "team_Id": finObj.group.id,
                        "team_name": finObj.group.name,
                        "supervisor_Id": "",
                        "source": "CISCO",
                        "created_by": "1"
                      }

                      config2.url = URL5;
                      config2.data = data;

                      try {

                        //Creating CX team of Agent
                        createAgentCXTeam = await requestController.httpRequest( config2, false );

                      } catch ( er ) {

                        let error = await errorService.handleError( er );

                        reject( {

                          error_message: "Error Occured While Creating CX Core Team To Add User In Finesse User Login (Update).",
                          error_detail: error
                        } );
                      }

                    }

                    //Assign Agent to a team
                    let URL6 = `${keycloakConfig[ "ef-server-url" ]}team/${finObj.group.id}/member`;

                    data = {
                      "type": "agent",
                      "usernames": [ finObj.username.toLowerCase() ]
                    }

                    config2.url = URL6;
                    config2.data = data;

                    try {

                      //Assigning Agent to CX team
                      let assignAgentToTeam = await requestController.httpRequest( config2, false );

                    } catch ( er ) {

                      let error = await errorService.handleError( er );

                      reject( {

                        error_message: "Error Occured While Assigning Agent to CX Core Team In Finesse User Login (Update).",
                        error_detail: error
                      } );
                    }

                  } catch ( er ) {

                    let error = await errorService.handleError( er );

                    reject( {
                      error_message: "Error Occured While Fetching User Team To Add User In Finesse User Login (Update).",
                      error_detail: error
                    } );

                  }
                }

                if ( !finObj.supervisedGroups && supervisedTeamsFiltered.length > 0 ) {

                  for ( let supervisedTeam of supervisedTeamsFiltered ) {

                    //Removing user from Supervising team in CX Core or not
                    let URL7 = `${keycloakConfig[ "ef-server-url" ]}team/${supervisedTeam.teamId}`;

                    let data = {
                      "team_name": supervisedTeam.teamName,
                      "supervisor_Id": null
                    }

                    config2.method = 'put';
                    config2.url = URL7;
                    config2.data = data;

                    try {

                      //Updating CX team of Supervisor
                      let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                    } catch ( er ) {

                      let error = await errorService.handleError( er );

                      reject( {

                        error_message: "Error Occured While Updating CX Core Team.",
                        error_detail: error
                      } );
                    }

                  }
                }

                //Supervisor Case. Filtering out teams to add and teams to remove from Supervisor
                //First check that We have supervised Groups in finesse
                if ( finObj.supervisedGroups ) {

                  let finesseSupervisedGroups = finObj.supervisedGroups;

                  // Fetching All the ids of CX Supervised Teams of current Supervisor
                  const teamIdsInSupervisedTeams = new Set( supervisedTeamsFiltered.map( team => team.teamId ) );

                  // Teams in which we need to add current user as Supervisor
                  const teamsToAddInCX = finesseSupervisedGroups.filter( item => !teamIdsInSupervisedTeams.has( item.id ) );

                  if ( teamsToAddInCX.length > 0 ) {

                    //Adding current user as supervisor in all the given teamsToAddInCX teams.
                    for ( let teamToAdd of teamsToAddInCX ) {

                      let supervisorTeamId = teamToAdd.id;

                      //Check whether team of Supervisor already exists in CX Core or not
                      let URL8 = `${keycloakConfig[ "ef-server-url" ]}team?ids=${supervisorTeamId}`;

                      config1.url = URL8;

                      try {

                        let getSupervisorCXTeam = await requestController.httpRequest( config1, false );

                        //This means the team doesn't exist in CX Core. We need to create a team
                        if ( getSupervisorCXTeam.data.length == 0 ) {

                          //Creating or Updating Supervisor team in CX Core.
                          let URL9 = `${keycloakConfig[ "ef-server-url" ]}team`;

                          let data = {
                            "team_Id": supervisorTeamId,
                            "team_name": teamToAdd.name,
                            "supervisor_Id": userId,
                            "source": "CISCO",
                            "created_by": "1"
                          }

                          config2.method = 'post';
                          config2.url = URL9;
                          config2.data = data;

                          try {

                            //Creating CX team of Supervisor
                            let createSupervisorCXTeam = await requestController.httpRequest( config2, false );

                          } catch ( er ) {

                            let error = await errorService.handleError( er );

                            reject( {

                              error_message: "Error Occured While Creating CX Core Team To Add Supervisor in Finesse User Login (Update).",
                              error_detail: error
                            } );
                          }

                        } else {

                          //Check whether team of Supervisor already exists in CX Core or not
                          let URL10 = `${keycloakConfig[ "ef-server-url" ]}team/${supervisorTeamId}`;

                          let data = {
                            "team_name": getSupervisorCXTeam.data[ 0 ].team_name,
                            "supervisor_Id": userId
                          }

                          config2.method = 'put';
                          config2.url = URL10;
                          config2.data = data;


                          try {

                            //Updating CX team of Supervisor
                            let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                          } catch ( er ) {

                            let error = await errorService.handleError( er );

                            reject( {

                              error_message: "Error Occured While Updating CX Core Team To Add Supervisor in Finesse User Login (Update).",
                              error_detail: error
                            } );
                          }


                        }

                      } catch ( er ) {

                        let error = await errorService.handleError( er );

                        reject( {

                          error_message: "Error Occured While Fetching CX Core Team To Add Supervisor in Finesse User Login (Update).",
                          error_detail: error
                        } );
                      }
                    }
                  }


                  // Fetching All the ids of Finesse Supervised Teams of current Supervisor
                  const idsInFinesseSupervisedGroups = new Set( finesseSupervisedGroups.map( item => item.id ) );

                  // Teams in which we need to remove current user as Supervisor
                  const teamsToRemoveFromCX = supervisedTeamsFiltered.filter( team => !idsInFinesseSupervisedGroups.has( team.teamId ) );

                  //Removing teams that Supervisor is not supervising anymore in finesse.
                  if ( teamsToRemoveFromCX.length > 0 ) {

                    for ( let supervisedTeam of teamsToRemoveFromCX ) {

                      //Removing user from Supervising team in CX Core or not
                      let URL11 = `${keycloakConfig[ "ef-server-url" ]}team/${supervisedTeam.teamId}`;

                      let data = {
                        "team_name": supervisedTeam.teamName,
                        "supervisor_Id": null
                      }

                      config2.method = 'put';
                      config2.url = URL11;
                      config2.data = data;

                      try {

                        //Updating CX team of Supervisor
                        let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                      } catch ( er ) {

                        let error = await errorService.handleError( er );

                        reject( {

                          error_message: "Error Occured While Updating CX Core Team To Remove Supervisor.",
                          error_detail: error
                        } );
                      }

                    }

                  }

                }

              } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {
                  error_message: "Error Occured While Fetching User Team in Finesse User Login (Update).",
                  error_detail: error
                } );

              }
            } catch ( err ) {

              reject( err );
            }
          } catch ( err ) {

            reject( err );
          }
        } catch ( err ) {

          reject( err );
        }
      } catch ( err ) {

        reject( err );
      }

      resolve( [] );
    } );
  }

  async checkPasswordUpdate( adminToken, userName, password ) {

    return new Promise( async ( resolve, reject ) => {

      let passwordUpdate = false;
      var URL = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig[ "realm" ] + "/users?search=" + userName + "&briefRepresentation=false"

      let config = {
        method: "get",
        url: URL,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`,
        }
      };

      try {

        //First check if the user exists or not in Keycloak, search user by username in Keycloak.
        let userResponse = await requestController.httpRequest( config, false );

        if ( userResponse.data.length > 0 ) {

          //Since user exists against username, now generate its access-token.
          /*
            If the access token is not generated, it means that password on
            Keycloak side is not valid and should be updated.
          */
          try {

            let tokenResponse = await this.getAccessToken( userName, password );

            if ( tokenResponse.access_token ) {

              resolve( [] );
            }

          } catch ( er ) {

            if ( er.error_detail.status == 401 ) {

              passwordUpdate = true;

            } else {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Error Occured While Generating User Access Token in Check Updated Password Component.",
                error_detail: error
              } );
            }

          } finally {

            if ( passwordUpdate ) {

              let userId = userResponse.data[ 0 ].id;

              //API URL used to update the password.
              var URL2 = keycloakConfig[ "auth-server-url" ] + "admin/realms/" + keycloakConfig[ "realm" ] + "/users/" + userId + "/reset-password"

              let data = {
                "temporary": false,
                "type": "password",
                "value": password
              }

              let config2 = {
                method: "put",
                url: URL2,
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${adminToken}`,
                },
                data: data
              };

              try {

                //Sending request to Update Password.
                await requestController.httpRequest( config2, false );

              } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                  error_message: "Error Occured While Updating Password of User in Check Updated Password Component.",
                  error_detail: error
                } );

              }

            }

          }


        }

        resolve( [] );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Error Occured While Searching for User by Username in Check Updated Password Component.",
          error_detail: error
        } );
      }
    } );
  }


  async generateAccessTokenFromRefreshToken( refreshToken ) {
    return new Promise( async ( resolve, reject ) => {
      let accessToken;
      var URL = keycloakConfig[ "auth-server-url" ] + "realms/" + keycloakConfig.realm + "/protocol/openid-connect/token";

      var config = {
        method: "post",
        url: URL,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: keycloakConfig.CLIENT_ID,
          client_secret: keycloakConfig.credentials.secret,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        },
      };

      try {
        let refreshTokenResponse = await requestController.httpRequest( config, true );

        let accessToken = refreshTokenResponse.data.access_token;
        resolve( {
          status: 200,
          access_token: accessToken,
        } );
      } catch ( error ) {
        if ( error.response ) {
          if ( error.response.data.error_description == "Token is not active" ) {
            error.response.data.error_description = "Refresh Token expired, please login again";
          }

          reject( {
            status: error.response.status,
            message: `${error.response.data.error_description}`,
          } );
        } else {
          reject( { message: error.message } );
        }
      }
    } );
  }

}

function checkForMissingRole( keycloakRealmRoles, requiredRoles ) {

  // Convert the object names to a Set for faster lookup
  const rolesNamesSet = new Set( keycloakRealmRoles.map( role => role.name ) );

  // Use the some method to check if at least one role is missing
  const isMissing = requiredRoles.some( role => !rolesNamesSet.has( role ) );

  return !isMissing;
}

function validateUser( userData ) {
  let schema = Joi.object( {
    username: Joi.string().min( 1 ).max( 255 ).required(),
    password: Joi.string().min( 1 ).max( 255 ).required(),
    token: Joi.string().required(),
    userRoles: Joi.array().items( Joi.string() ).allow( null ),
  } );

  return schema.validate( userData );
}

module.exports = KeycloakService;