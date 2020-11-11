
<h1>Node JS module for keycloak</h1>

This module can be installed with
* __sudo npm install keycloak_adapter__

This module can be used by importing index.js file in your application like this
* _require("./node_modules/keycloak_adapter/index.js");_

Index.js have a class called __NodeAdapter__ which have following functions:
* userAuthentication
* createResource
* deleteResource
* permitUsertoResoucre
* resoucreAuthorization
* revokeUseronResource

```
Each function can be called like this
 let nodeAdapter = require("./node_modules/keycloak_adapter/index.js");
 let adapter= nodeAdapter.NodeAdapter;
 let obj1=new adapter();
 obj1.userAuthentication();
```


You need to have a __keycloak.json file__ in the _root_ directory which contains all the configurations.
Sample file is given below:

```{
  "realm": "university",
  "auth-server-url": "http://192.168.1.47:8080/auth/",
  "ssl-required": "external",
  "resource": "Banks",
  "verify-token-audience": true,
  "credentials": {
    "secret": "2e991b1c-d340-437d-91a2-620465c51a4e"
  },
  "confidential-port": 0,
  "policy-enforcer": {},
  "CLIENT_ID": "Bank",
  "CLIENT_SECRET": "2e991b1c-d340-437d-91a2-620465c51a4e",
  "CLIENT_DB_ID": "95536d4e-c5d5-4876-8cc3-99025e18fc60",
  "GRANT_TYPE": "password",
  "HOST": "192.168.1.47",
  "PORT": "8080",
  "REALM": "university",
  "GRANT_TYPE_PAT": "client_credentials",
  "USERNAME_ADMIN": "admin2",
  "PASSWORD_ADMIN": "admin2",
  "SCOPE_NAME": "bank-account-scope"
}
```
__Detail of functions is given below:__
```
userAuthentication(user_name, user_password)
This function takes two parameters. It then ask keycloak whether user exists in keycloak or not. If user exists it returns an access_token which have all the roles,permissions and other data against that user.
```
```
createResource(resource_name, resource_scope = "bank-account")
This function takes 2 parameters in which one is default. The default value is defined in the keycloak.json file. We only pass resource_name into a function and it creates a resource in keycloak client under Authorization tab.
```
```
deleteResource(resource_name) 
This function takes just one parameter as a resource_name and then deletes the requested resource in keycloak.
```
```
permitUsertoResoucre(resource_name, keycloak_user_id)
This function takes user_id and make a user based policy for that user. It then assign that policy to permission and then associate that permission with the resource.
```
```
resoucreAuthorization(keycloak_user_id, resource_name) 
This function evaluates whether the user is allowed access to the resource. In case of true it return “Permit” else “Deny”.
```
```
revokeUseronResource = (resource_name, keycloak_user_id) 
This function is used to delete policy and permissions associated with a keycloak_user_id to a resource.
```

 
