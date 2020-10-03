const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', function(req, res) {
	res.status(401);
	let reqId = randomString();
	reqClient = req.query.client_id;
	if (reqClient in clients) {
		reqScope = req.query.scope.split(" ");
		if(containsAll(
				clients[reqClient].scopes, 
				reqScope)) {
			res.status(200);
			requests[reqId] = req.query;
			return res.render('login', 
									{
										'client': clients[reqClient],
										'scope': reqScope,
										'requestId': reqId
									});
		}
	}
	return res.end();
});

app.post('/approve', function(req, res) {
	let un = req.body.userName;
	let pw = req.body.password;
	let reqId = req.body.requestId;  

	if( users[un] === pw && requests[reqId]) {
		let request = requests[reqId];
		let authKey = randomString();

		delete requests[reqId];
		
		authorizationCodes[authKey] = {
			clientReq: request,
			userName: un
		}
		
		let redirectURL = new URL(request.redirect_uri);
		redirectURL.searchParams.set('code', authKey);
		redirectURL.searchParams.append('state', request.state);
		return res.redirect(302, redirectURL.toString());
		// return res.status(200).end();
	}
	return res.status(401).end();
});

app.post('/token', function(req, res) {
	if(req.headers.hasOwnProperty('authorization')) {
		let authObj = decodeAuthCredentials(req.headers.authorization);
		if(clients[authObj.clientId] && 
			clients[authObj.clientId].clientSecret === authObj.clientSecret) {
			return res.status(200).end();
		}
	} 
		return res.status(401).end();
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
