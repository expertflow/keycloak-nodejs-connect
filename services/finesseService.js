var requestController = require("../controller/requestController.js");
const https = require('https');

class FinesseService {

    constructor() {

    }


    async authenticateUserViaFinesse(username, password, finesseUrl) {

        return new Promise(async (resolve, reject) => {

            var URL = finesseUrl + '/finesse/api/User/' + username;

            let encodedCredentials = await this.maskCredentials(username, password);

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Basic ${encodedCredentials}`
                },
                //disable ssl
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, true);

                resolve({
                    'status': tokenResponse.status
                });

            }
            catch (er) {

                if (er.code == "ENOTFOUND") {

                    resolve({
                        'finesse login status': 408,
                        'finesse login message': `finesse server not accessible against URL: ${finesseUrl}`
                    });

                } else if (er.response) {

                    resolve({
                        'finesse login status': er.response.status,
                        'finesse login message': er.response.statusText
                    });

                }

            }

        });
    }

    async authenticateUserViaFinesseSSO(username, finesseToken, finesseUrl) {

        return new Promise(async (resolve, reject) => {

            var URL = finesseUrl + '/finesse/api/User/' + username;

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Bearer ${finesseToken}`
                },
                //disable ssl
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, true);

                resolve({
                    'status': tokenResponse.status
                });

            }
            catch (er) {

                if (er.code == "ENOTFOUND") {

                    resolve({
                        'finesse login status': 408,
                        'finesse login message': `finesse server not accessible against URL: ${finesseUrl}`
                    });

                } else if (er.response) {

                    resolve({
                        'finesse login status': er.response.status,
                        'finesse login message': er.response.statusText
                    });

                }
            }

        });
    }

    async getCiscoTeams(username, password, finesseUrl) {

        return new Promise(async (resolve, reject) => {

            var URL = finesseUrl + '/finesse/api/Teams';

            let encodedCredentials = await this.maskCredentials(username, password);

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Basic ${encodedCredentials}`
                },
                //disable ssl
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, true);

                resolve(tokenResponse.data);

            }
            catch (er) {

                if (er.code == "ENOTFOUND") {

                    resolve({
                        'finesse login status': 408,
                        'finesse login message': `finesse server not accessible against URL: ${finesseUrl}`
                    });

                } else if (er.response) {

                    resolve({
                        'finesse login status': er.response.status,
                        'finesse login message': er.response.statusText
                    });

                }

            }

        });
    }

    async getCiscoUsers(username, password, finesseUrl) {

        return new Promise(async (resolve, reject) => {

            var URL = finesseUrl + '/finesse/api/Users';

            let encodedCredentials = await this.maskCredentials(username, password);

            let config = {
                method: 'get',
                url: URL,
                headers: {
                    'Authorization': `Basic ${encodedCredentials}`
                },
                //disable ssl
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            };

            try {

                let tokenResponse = await requestController.httpRequest(config, true);

                resolve(tokenResponse.data);

            }
            catch (er) {

                if (er.code == "ENOTFOUND") {

                    resolve({
                        'finesse login status': 408,
                        'finesse login message': `finesse server not accessible against URL: ${finesseUrl}`
                    });

                } else if (er.response) {

                    resolve({
                        'finesse login status': er.response.status,
                        'finesse login message': er.response.statusText
                    });

                }

            }

        });
    }

    async maskCredentials(username, password) {

        let token = Buffer.from(`${username}:${password}`, 'utf8').toString('base64');
        return token;

    }
}

module.exports = FinesseService;