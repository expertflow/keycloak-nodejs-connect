var requestController = require("../controller/requestController.js");
const https = require('https');
var keycloakConfig = require("../config.json");

class FinesseService{

    constructor() {

    }


    async authenticateUserViaFinesse(username,password){

        return new Promise(async (resolve, reject) => {
            
            var URL = keycloakConfig["finesse-server-url"] + '/finesse/api/User/' +username;
            
            let encodedCredentials = await this.maskCredentials(username,password); 

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Basic ${encodedCredentials}`
                },
                //disable ssl
                httpsAgent: new https.Agent({rejectUnauthorized: false})
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, true);
                resolve(tokenResponse.status);

            }
            catch (er) {
                reject(er);
            }

        });
    }

    async maskCredentials(username, password){

        let token = Buffer.from(`${username}:${password}`, 'utf8').toString('base64');
        return token;

    }
}

module.exports = FinesseService;