
# Node JS module for keycloak
Keycloak is an Open Source Identity and Access Management solution for modern Applications and Services.

This repository contains the source code for the Keycloak Node.js adapter. This module makes it simple to implement a Node.js Connect-friendly application that uses Keycloak for its authentication and authorization needs.

[Documentation](https://www.keycloak.org/documentation.html)

## Getting started

### Installation 
```javascript
 npm install keycloak-nodejs-connect
 ```
 
## Usage
```
This adapter is extended from keycloak-connect and have functionalities of both adapters.
```
### Functions
```
 authenticateUserViaKeycloak
 getUsersByRole
 createResource
 deleteResource
 permitUsertoResoucre
 resoucreAuthorization
 revokeUseronResource
```
### Example

```
  var {NodeAdapter} = require("keycloak-nodejs-connect");
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
keycloak.authenticateUserViaKeycloak('admin', 'admin','cim').then((e) => {
    console.log("result :" + (e));
}).catch((er) => {
    console.log("reject error : " + er);
});
```

Sample `config` is given below:

```
{
  "realm": "cim",
  "auth-server-url": "http://192.168.1.204:8080/auth/",
  "ssl-required": "external",
  "resource": "unified-admin",
  "verify-token-audience": false,
  "credentials": {
    "secret": "27080cdf-cdd8-4db1-b3ee-fdb0669b0222"
  },
  "use-resource-role-mappings": true,
  "confidential-port": 0,
  "policy-enforcer": {},
  "CLIENT_ID": "unified-admin",
  "CLIENT_DB_ID": "95536d4e-c5d5-4876-8cc3-99025e18fc60",
  "GRANT_TYPE": "password",
  "GRANT_TYPE_PAT": "client_credentials",
  "USERNAME_ADMIN": "uadmin",
  "PASSWORD_ADMIN": "uadmin",
  "SCOPE_NAME": "Any deafult scope",
  "bearer-only":true
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
