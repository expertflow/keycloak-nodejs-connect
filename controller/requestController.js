const axios = require('axios')
const qs = require('querystring');
module.exports={

//flag identifies which configuration to be sent as stringified 

httpRequest : (config,flag)  => {
    var localConfig =  {...config};
    if(flag){
        localConfig.data=qs.stringify(localConfig.data);
    }
    return axios(localConfig);
    }
}
