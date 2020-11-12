
# Node JS module for keycloak
Keycloak is an Open Source Identity and Access Management solution for modern Applications and Services.

This repository contains the source code for the Keycloak Node.js adapter. This module makes it simple to implement a Node.js Connect-friendly application that uses Keycloak for its authentication and authorization needs.

[Documentation](https://www.keycloak.org/documentation.html)

## Getting started

### Installation 
```javascript
 npm install keycloak_adapter
 ```
 
## Usage

### Functions
```
 userAuthentication
 createResource
 deleteResource
 permitUsertoResoucre
 resoucreAuthorization
 revokeUseronResource
```
### Example

```
  let Keycloak = require("keycloak_adapter");
  let keycloak= Keycloak.NodeAdapter;
```

Each function returns a promise so

```
keycloak.userAuthentication('agent1', 'agent1').then((e) => {
    console.log(e;
}).catch((er) => {
    console.log(er);
});
```

You need to have a __keycloak.json file__ in the _root_ directory which contains all the configurations.
Sample file is given below:

```{
  "HOST": "192.168.1.47",
  "PORT": "8080",
  "ssl-required": "external",
  "resource": "Banks",
  "verify-token-audience": true,
  "confidential-port": 0,
  "policy-enforcer": {},

  "CLIENT_ID": "Bank",
  "CLIENT_SECRET": "2e991b1c-d340-437d-91a2-620465c51a4e",
  "CLIENT_DB_ID": "95536d4e-c5d5-4876-8cc3-99025e18fc60",
  "GRANT_TYPE": "password",
  "REALM": "university",
  "GRANT_TYPE_PAT": "client_credentials",
  "USERNAME_ADMIN": "_any user in realm with all roles_",
  "PASSWORD_ADMIN": "_any user in realm with all roles_",
  "SCOPE_NAME": "Any deafult scope"
}
```
__Functions Description__

##### userAuthentication(user_name, user_password)
```
This function ask keycloak whether user exists in keycloak or not. If user exists it returns an access_token with all the roles,permissions and other data against that user.
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