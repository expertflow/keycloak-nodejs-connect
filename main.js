let nodeAdapter = require("./index.js");
let adapter= nodeAdapter.NodeAdapter;
let obj1=new adapter();

obj1.userAuthentication('agent1', 'agent1').then((e) => {
    console.log("result :" + Object.entries(JSON.parse(JSON.stringify(e.data))));
}).catch((er) => {
    console.log("reject error : " + er);
});

/*
obj1.createResource("saqib").then((e) => {
    console.log("result :" + Object.entries(JSON.parse(JSON.stringify(e.data))));
}).catch((er) => {
    console.log("reject error : " + er);
});
*/
/*
obj1.deleteResource("saqib").then((e) => {
    console.log("result :" + Object.entries(JSON.parse(JSON.stringify(e.data))));
}).catch((er) => {
    console.log("reject error : " + er);
});
*/
/*
obj1.permitUsertoResoucre("saqib","ff323370-ef19-46b7-b41a-07834083d064").then((e) => {
    console.log("result :" + Object.entries(JSON.parse(JSON.stringify(e.data))));
}).catch((er) => {
    console.log("reject error : " + er);
});
*/
/*
obj1.ResoucreAuthorization("ff323370-ef19-46b7-b41a-07834083d064","saqib").then((e) => {
    console.log("result :" + Object.entries(JSON.parse(JSON.stringify(e.data))));
}).catch((er) => {
    console.log("reject error : " + er);
});
*/
/*
obj1.revokeUseronResource("saqib","ff323370-ef19-46b7-b41a-07834083d064").then((e) => {
    console.log("result :" + (JSON.stringify(e.data)));
}).catch((er) => {
    console.log("reject error : " + er);
});
*/