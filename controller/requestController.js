const axios = require('axios')
const qs = require('querystring');
module.exports={
httpRequest : (config,flag)  => {   //flag identifies which configuration to be sent as stringified 
    var localConfig =  {...config};
    if(flag){
        localConfig.data=qs.stringify(localConfig.data);
    }
    return axios(localConfig);
    }
}
