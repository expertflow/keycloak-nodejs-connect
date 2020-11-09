const axios = require('axios')
const qs = require('querystring');
module.exports={

httpRequest : (config,flag)  => {

    return new Promise((resolve, reject) => {

        if(flag){
            config.data=qs.stringify(config.data);
            axios(config)
            .then((response) => {
                config.data=qs.parse(config.data);
                resolve(response);
            }).catch((er) => {
                reject(er);
            });
        }
        else{
            axios(config)
            .then((response) => {
                resolve(response);
            }).catch((er) => {
                reject(er);
            });
        }
    });
 }
};