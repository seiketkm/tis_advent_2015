"use strict"
let https = require('https'),
fs    = require('fs'),
util  = require('util'),
url   = require('url');

let httpsServ = https.createServer(
    {
	requestCert: true,
	rejectUnauthorized: true,
	key:  fs.readFileSync ('./sample/server-key.pem'),
	cert: [fs.readFileSync('./sample/server-crt.pem')],// クライアント側で検証される証明書の設定
	ca:   [fs.readFileSync('./sample/ca-crt.pem')],　// オレオレ認証局（検証用）
    },
    (req, res) => {
	// Getパラメータで渡されるOrg
	let orgByParam = url.parse(req.url, true).query.o || '';
	// 実際の接続時に利用された証明書のOrg
	let cert = res.connection.getPeerCertificate();
	let orgByCert = cert.subject ? cert.subject.O : '';
//	res.write(util.format(cert)); // for debug
	
	//　出力用文字列作成(console.logとresponse body)
	let outText = 
	    "Param:" +orgByParam + '\n' +
	    "Org  :" +orgByCert + '\n';
	// 一致しない場合406
	if(orgByParam !== orgByCert && orgByCert !== ''){
	    res.statusCode = 406 //Not Acceptable	    
	}
	// 出力
	console.log(outText);
	res.write(outText);
	//res.write(util.format(cert)); // for debug

	res.end();
    }
).listen(
    8000, 
    () => console.log("start Server")
);
