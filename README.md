# Node JS adapter for keycloak
Keycloak is an Open Source Identity and Access Management solution for modern Applications and Services.

This repository contains the source code for the Keycloak Node.js adapter. This module makes it simple to implement a Node.js Connect-friendly application that uses Keycloak for its authentication and authorization needs.

[Documentation](https://www.keycloak.org/documentation.html)

# EF Keycloak Connect

**ef-keycloak-connect** extends on the functionality of Keycloak Node JS adapter by using Keycloak APIs to simplify its functionality. This package provides functions to Authencticate a user, get access token with introspect, create and delete resource, create users, roles and assign role to users. 

**ef-keycloak-connect** also includes the functions to authenticate users from Cisco Finesse for both SSO and Non SSO instances.

## Getting started

### Installation 
```javascript
 npm install ef-keycloak-connect
 ```
 
## Usage
```
This adapter is extended from keycloak-connect and have functionalities of both adapters.
```
### Functions
```
  - authenticateUserViaKeycloak
  - getAccessToken
  - getKeycloakTokenWithIntrospect
  - createResource
  - deleteResource
  - createPolicy
  - createPermission
  - resourceAuthorization
  - createUser
  - getUsersByRole
  - getRealmRoles
  - assignRoleToUser
  - authenticateFinesse
  
```
### Example

```
  var {NodeAdapter} = require("ef-keycloak-connect");
  const config = require(`${Path_To_Config_File}`);
  const keycloak = new NodeAdapter(config)

```
  Note here that `config` object is passed as a parameter to constructor of NodeAdapter class. 
  You can put all the configuration in a file and them import that file in your application
  OR
  You can create an object containing all the configurations and pass it.


Each function returns a promise so

```
keycloak.authenticateUserViaKeycloak('admin', 'admin','cim',`https://${finesse_server_url}:${port}`, ['role1','role2'], 'finesseToken').then((e) => {
    console.log("result :" + (e));
}).catch((er) => {
    console.log("reject error : " + er);
});

```
  Note: Above mentioned function is used to authenticate a user, the function returns a promise containing either **access_token** or generate an error. 
 

Sample `config` is given below:

```
{
  "realm": "keycloak_realm_name",
  "auth-server-url": "http://keycloak_server_url}:port/auth/",
  "ssl-required": "external",
  "resource": "keycloak_resource_name",
  "verify-token-audience": false,
  "credentials": {
    "secret": "keycloak_client_secret"
  },
  "use-resource-role-mappings": true,
  "confidential-port": 0,
  "policy-enforcer": {},
  "CLIENT_ID": "keycloak_resource_name",
  "CLIENT_DB_ID": "keycloak_client_secret",
  "GRANT_TYPE": "password",
  "GRANT_TYPE_PAT": "client_credentials",
  "USERNAME_ADMIN": "admin_name",
  "PASSWORD_ADMIN": "admin_password",
  "SCOPE_NAME": "Any default scope",
  "bearer-only": true
}
```
Here is the definition of each property defined in config file/object.

- **realm:** Name of your keycloak realm (A realm manages a set of users, credentials, roles, and groups.)
- **auth-server-url:** URL of your keycloak instance, its either ip with port or fqdn of your keycloak instance.
- **ssl-required:** Each realm has an SSL Mode associated with it. The SSL Mode defines the SSL/HTTPS requirements for interacting with the realm. we are using ssl-required as **external** which means Users can interact with Keycloak without SSL so long as they stick to private IP addresses like localhost, 127.0.0.1, 10.x.x.x, 192.168.x.x, and 172.16.x.x
- **resource:** your keycloak client name. (Clients are entities that can request Keycloak to authenticate a user).
- **verify-token-audience:** we keep it as **false** (If set to true, then during authentication with the bearer token, the adapter will verify whether the token contains this client name (resource) as an audience).
- **credentials:** It contains a client secret key.
- **use-resource-role-mappings:** If set to true, the adapter will look inside the token for application level role mappings for the user. If false, it will look at the realm level for user role mappings. This is OPTIONAL. The default value is false.
- **confidential-port:** We keep its value as 0 (The confidential port used by the Keycloak server for secure connections over SSL/TLS. This is OPTIONAL. The default value is 8443.)
- **policy-enforcer:** we keep it as an empty object i.e {}
- **CLIENT_ID:** The name of client application inside keycloak realm.
- **CLIENT_DB_ID:** Its value is same as **client_secret**
- **GRANT_TYPE:** will keep its value as **password** (The Grant Type is a way to exchange a user's credentials for an access token)
- **GRANT_TYPE_PAT:** will keep its value as **client_credentials** (A protection API token (PAT) is a special OAuth2 access token with a scope defined as uma_protection) 
- **USERNAME_ADMIN:** Keycloak realm admin username.
- **PASSWORD_ADMIN:** Keycloak realm admin password.
- **SCOPE_NAME:** Keycloak Client App scope to use as default scope during Authorization.
- **bearer-only** will keep its value as **true** (This should be set to true for services. If enabled the adapter will not attempt to authenticate users, but only verify bearer tokens. This is OPTIONAL. The default value is false.)

```
For using keycloak-connect features 

var express = require('express');
var app = express();
var session = require('express-session');
var memoryStore = new session.MemoryStore();

app.use(session({
    secret: 'secret1',
    resave: false,
    saveUninitialized: true,
    store: memoryStore
}));

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0    // to disable https

app.use( keycloak.middleware({ logout: '/logout' }))

app.get('/', (req, res) => {
    console.log('Heloo - - -- - ');
    res.send('Heloo - - -- - ');
});

app.get('/home', keycloak.protect(), (req, res) => {
    console.log('Home accessed..');
    res.send('Welcome to Home');
});

app.get( '/notdefined', keycloak.protect('realm:app-user'),(req,res) => {
    console.log("not defined")
    res.send("This resource is not defined in keycloak. User with app-user role can access this API")
});

app.get('/amq', keycloak.enforcer(['amq:view-amq'], {
    resource_server_id: 'unified-admin'
  }), function (req, res) {
    console.log("not defined")
    res.send("AMQ settings resource accessed")
 });

 app.post('/amq', keycloak.enforcer(['amq:create-amq'], {
    resource_server_id: 'unified-admin'
  }), function (req, res) {
    console.log("not defined")
    res.send("AMQ settings resource accessed")
 });

var server = app.listen(3000, function () {
    // var host = server.address().address
    // var port = server.address().port
    console.log(`Example app listening at http://%s:%s`)
})
```

## Functions Description

  >  This is the elaboration of functions exposed by EF Keycloak Adapter. It contains each function name, the arguments/parameters it take and the response each function generate.


### authenticateUserViaKeycloak(user_name, user_password, realm_name, finesse_server_url, user_roles, finesse_token)

This function performs 3 functionalities based on arguments/parameters provided.

   - Finesse User Auth and Sync with keycloak (Non SSO).
   - Finesse User Auth and Sync with keycloak (SSO).
   - Keycloak Authentication of User.

 
 It takes 6 arguments (3  of them are only used for Finesse User Auth ):
 
  - user_name: The name of user to authenticate.
  - user_password: The password of user to authenticate.(In case of Finesse SSO instance the password will be empty string i.e **' '**)
  - realm_name: Keycloak realm in which current user exits.
  - finesse_server_url: The url of finesse server (In case of normal keycloak auth, send this parameter as **' '**)
  - user_roles: The array containing user_roles, it will be used to assign roles to finesse user while synching it with Keycloak (for normal auth send it as [ ]).
  - finesse_token: acess token for finesse SSO authentication (It will only be passed if Finesse SSO instance is connected, in any other case we will pass empty string **' '** as argument)

***Finesse User Auth and Sync with keycloak (Non SSO)***
 For Finesse User Auth (Non SSO) we use the function as follows
 ```
  authenticateUserViaKeycloak('admin_username', 'admin_password','realm_name',`https://${finesse_server_url}:${port}`, ['role1','role2'],'')
 ```
 Finesse User Auth first authenticates user from finesse, then check for its existance in keycloak. If it exists in keycloak then generates an access_token along with role mapping and return it to user. If user doesn't exist then it creates a user, assign it roles and return the access_token along with role mapping for newly created user.
 
***Finesse User Auth and Sync with keycloak (SSO)***
 For Finesse User Auth (Non SSO) we use the function as follows
   ```
   authenticateUserViaKeycloak('admin_username', '',,'realm_name', `https://${finesse_server_url}:${port}`, ['agent','supervisor'], 'finesse_token')
   ```
  Difference between *Finesse User Auth(SSO)* and *Finesse User Auth(Non SSO)* is that SSO uses finesse_token field while Password field remains ' ', while in Non SSO a Password is sent by user and finesse_token field remains ' '
  
***Keycloak Authentication of User***
For Keycloak User Auth, we use the function as follows:

```
 authenticateUserViaKeycloak('admin_username', 'admin_password','realm_name','', [],'')
```

 Keycloak User Auth ask keycloak whether user exists in keycloak realm or not. If user exists it returns a KeyCloakUser object with the user information.
 
### getAccessToken(user_name, user_password)

This function Authenticates a Keycloak user if exists in given realm and return an object containing access_token, refresh_token but not the role mapping of User.

It takes 2 arguments: 

   - user_name: The name of user to authenticate.
   - user_password: The password of user to authenticate. 

### getKeycloakTokenWithIntrospect(user_name, user_password, realm_name)

This function Authenticates a Keycloak user if exists in given realm and return an object containing access_token, refresh_token along with role mapping of User used for Authorization.

It takes 3 arguments: 

   - user_name: The name of user to authenticate.
   - user_password: The password of user to authenticate.
   - realm_name: Keycloak realm in which current user exits.

### createResource(resource_name, resource_scope = env.SCOPE_NAME)

This function creates a resource in keycloak. Resource can be either webpage, api or microservice to be secured by Authorization, resource contains scopes. Each scope define the functionality that can be performed on resource, scope is independent of Resource.

It takes 2 arguments:
   
   - resource_name: The name of resource to be secured.
   - resource_scope: The scope to be linked to this resource,by default we take scope from our config file.

### deleteResource(resource_name) 

As name suggests, it deletes a resource from Keycloak client.

It takes a single argument:
 
 - resource_name: The name of resource to be deleted.

### createPolicy(policyName, roles)

While implementing Authorization mechanism, we need to create policy to apply permissions, there are multiple types of policies that we can create in Keycloak i.e role_based, client_based, time_based, user_based etc. We recommend you to use role_based policies, the above function is used to create role_based policies.

It takes 2 arguments:
   
   - policyName: The name of role_based policy.
   - roles: All the roles linked to this role based policy. its an array of roles i.e ['admin','agent']

### createPermission(resourceName, policyName, permissionName, scopeName)

This functions creates permission by applying specific policy to certain resource containing scopes. For example, a permission that only a user with admin role (role based policy) can edit(scope) a profile of user (resource).

It takes 4 arguments:
   
  - resourceName: The name of the resource.
  - policyName: The name of policy to be connected with resource.
  - permissionName: The name of permission linking policy, scope and resource.
  - scopeName: The name of scope to be approved in this permission against certain resource on approval of policy.

### resoucreAuthorization(keycloak_user_id, resource_name) 

This function evaluates whether the user is allowed access to the resource. In case of true it return “Permit” else “Deny”.

It takes 2 arguments: 

  - keycloak_user_id: The id of user whose access has been checked.
  - resource_name: The name of resource on which the access is being checked.

### getUsersByRole(keycloak_roles) 

This function returns a list of users against a certain role, the role is passed as parameter in function

It take a single argument:
  - keycloak_roles: Array of roles i.e ['admin','agent']

### createUser(username,password,token,userRoles)

This function create a user inside given keycloak realm. It require an admin token for permission to create User, it takes userRoles as an optional argument.

It takes 4 arguments:

   - username: name of user to be created.
   - password: password of the user.
   - token: admin token, needed to grant permission to create user.
   - userRoles: array of roles to be assigned to newly created user i.e: ['agent','supervisor'].

### assignRoleToUser(userId, roles, adminToken)

This function assign a given role/(list of roles) to given user, it requires an admin token to authorize assignment of roles.

It takes 3 arguments: 

   - userId: the id of user who is requesting for roles.
   - roles: The list of role or single role to be assigned i.e ['agent'].
   - adminToken: admin token, needed to authorize the assignment of roles.

### getRealmRoles(adminToken)

This function returns the list of all the available roles in keycloak realm.

It takes a signle argument:

   - adminToken: Admin token is required to authorize the list of roles to return.

### authenticateFinesse(username, password, finesseUrl, userRoles, finesseToken)

This function sync finesse user in keycloak, it first authenticates user from finesse, then check for its existance in keycloak. If it exists in keycloak then generates an access_token along with role mapping and return it to user. If user doesn't exist then it creates a user, assign it roles and return the access_token along with role mapping for newly created user.

It takes 5 arguments: 
 - user_name: The name of user to authenticate.
 - user_password: The password of user to authenticate.(In case of Finesse SSO instance the password will be empty string i.e **' '**)
 - finesse_server_url: The url of finesse server (In case of normal keycloak auth, send this parameter as **' '**)
 - user_roles: The array containing user_roles, it will be used to assign roles to finesse user while synching it with Keycloak (for normal auth send it as [ ]).
 - finesse_token: acess token for finesse SSO authentication (It will be passed if Finesse SSO instance is connected, in case of non SSO will pass empty string **' '** as argument)
 
 ##### Example of SSO Finesse Auth:
 
      
        authenticateFinesse('admin_username', '', `https://${finesse_server_url}:${port}`, ['agent','supervisor'], 'finesse_token')
        
 ##### Example of non SSO Finesse Auth:
      
      authenticateFinesse('admin_username', 'admin_password', `https://${finesse_server_url}:${port}`, ['agent','supervisor'], '')

### generateAccessTokenFromRefreshToken(refreshToken)

This function generates a new access_token by using the refreshToken received in parameter.

It takes a signle argument:

   - refreshToken: Refresh Token is used to generate the new access token.

Response:

  - If the refresh token is valid then a new access token is returned in reponse along with status code 200. 
    
    ``` 
    {
      "status": 200,
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqeEMzZDV5VVZRS1ktY3MwSmhQd29DVzllNjB0VkFPQXBIUDlWUlhsejdBIn0.eyJleHAiOjE2NzgyNzIzNDEsImlhdCI6MTY3ODI3MjEwNSwianRpIjoiNWVkMDBiYzgtNDM1MC00MjQ2LTllOTEtYjE4ZGIyMzc5YTI2IiwiaXNzIjoiaHR0cDovLzE5Mi4xNjguMS4yMDQ6ODA4MC9hdXRoL3JlYWxtcy9EZW1vLUtleWNsb2FrLVJlYWxtIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjY5OGRkYWFkLTZkZTYtNDY1YS04Mjg1LTQ4MWI5NjZjMmYxNiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRlbW8ta2V5Y2xvYWstY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6ImM2NTNmNDk5LWJlNzMtNDIyNS05MGU4LThkYjBjNDkwYTc5MCIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1kZW1vLWtleWNsb2FrLXJlYWxtIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsImFnZW50LXJvbGUiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJhdXRob3JpemF0aW9uIjp7InBlcm1pc3Npb25zIjpbeyJyc2lkIjoiNDBhNzg1MjYtNjNiNy00NDcwLThkZWEtZjRlZDViNTUwOTUzIiwicnNuYW1lIjoiRGVmYXVsdCBSZXNvdXJjZSJ9XX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6ImM2NTNmNDk5LWJlNzMtNDIyNS05MGU4LThkYjBjNDkwYTc5MCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6InphcnlhYiByYXphIiwiYWdlbnRFeHRlbnNpb24iOiI4MDgxLDYwMDEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ6YXJ5YWIgcmF6YSIsImdpdmVuX25hbWUiOiJ6YXJ5YWIiLCJmYW1pbHlfbmFtZSI6InJhemEiLCJlbWFpbCI6InphcnlhYkBlbWFpbC5jb20ifQ.Y8NVa0OzAPBwtb6cGyhZxMEyv-o_nTA9ZcvXNcmcEMivqTT0dTE95yNKXYxUQuhTAWE6mPJDwuZ0GuEco7hhxQ6IjjH2j0QwjvqEFFi7KNNdIi-yS4q0elNCjxar8zkHY3Gy8a2d7C_9CQuBN-ernV-JYcmGHENlpmJJpyHfZ5aNkzrcHN5b9qDx2-YZm8pkgFuUv8bwogFFeECzclOlrSGHmaiOI1gp2jkUIw8q23LB8YvzdVg5aHgSDcTKD4gXRrG7C_OQRbCmycOtW4iECLlURnlbbF5Rq4vxzrHjRtBAQmVZ86ITP7yDqEPOWfIxHjODDWWHNL2r7dK8OhNK_g"
    }

 - If the refresh token is invalid then an error message is returned in reponse along with status code 400.
 
 ```
   {
     "status": 400,
     "message": "Refresh Token expired, please login again"
   }
      
       
