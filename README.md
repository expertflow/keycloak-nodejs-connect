
# Node JS module for keycloak
Keycloak is an Open Source Identity and Access Management solution for modern Applications and Services.

This repository contains the source code for the Keycloak Node.js adapter. This module makes it simple to implement a Node.js Connect-friendly application that uses Keycloak for its authentication and authorization needs.

[Documentation](https://www.keycloak.org/documentation.html)

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
  authenticateUserViaKeycloak
  getAccessToken
  getKeycloakTokenWithIntrospect
  createResource
  deleteResource
  createPolicy
  createPermission
  resourceAuthorization
  revokeUseronResource
  createUser
  getUsersByRole
  getRealmRoles
  assignRoleToUser
  authenticateFinesse
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
  ```

```

Each function returns a promise so

```
keycloak.authenticateUserViaKeycloak('admin', 'admin','cim',`https://${finesse_server_url}:${port}`, ['role1','role2']).then((e) => {
    console.log("result :" + (e));
}).catch((er) => {
    console.log("reject error : " + er);
});

   ```
  Note: We use the same function to either **Authenticate Finesse User** or **Authenticate Via Keycloak**. In case of **Finesse Auth** we pass 2 additional params i.e Finesse Url & Roles Array, in case of **Authenticate Via Keycloak** we just send Finesse Url as empty string i.e ''
  ```
```

Sample `config` is given below:

```
{
  "realm": "keycloak_realm_name",
  "auth-server-url": "http://keycloak_server_url}:port/auth/",
  "ssl-required": "external",
  "resource": "keycloak_resource_name",
  "verify-token-audience": false,
  "credentials": {
    "secret": "461d914e-4b22-4978-8c67-7fe0dfe45d86"
  },
  "use-resource-role-mappings": true,
  "confidential-port": 0,
  "policy-enforcer": {},
  "CLIENT_ID": "keycloak_resource_name",
  "CLIENT_DB_ID": "461d914e-4b22-4978-8c67-7fe0dfe45d86",
  "GRANT_TYPE": "password",
  "GRANT_TYPE_PAT": "client_credentials",
  "USERNAME_ADMIN": "admin_name",
  "PASSWORD_ADMIN": "admin_password",
  "SCOPE_NAME": "Any default scope",
  "bearer-only": true
}
```


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
__Functions Description__

   ```
     This is the elaboration of functions exposed by EF Keycloak Adapter. It contains each function name, the arguments/parameters it take and the response each function generate.
   ```

##### authenticateUserViaKeycloak(user_name, user_password, realm_name)
```
This function ask keycloak whether user exists in keycloak realm or not. If user exists it returns a KeyCloakUser object with the user information.
```

##### createResource(resource_name, resource_scope = env.SCOPE_NAME)
```
This function creates a resource in keycloak. The default value is defined in the keycloak.json file. We only pass resource_name into a function and it creates a resource in keycloak client under Authorization tab.
```
##### deleteResource(resource_name) 
```
This function takes just one parameter as a resource_name and then deletes the requested resource in keycloak.
```

##### permitUsertoResoucre(resource_name, keycloak_user_id)
```
This function takes user_id and make a user based policy for that user. It then assign that policy to permission and then associate that permission with the resource.
```

##### resoucreAuthorization(keycloak_user_id, resource_name) 
```
This function evaluates whether the user is allowed access to the resource. In case of true it return “Permit” else “Deny”.
```

##### revokeUseronResource = (resource_name, keycloak_user_id) 
```
This function is used to delete policy and permissions associated with a keycloak_user_id to a resource.
```
#####   getUsersByRole(keycloak_roles) 
```
This function is used to get users having roles (passed in parameter)
