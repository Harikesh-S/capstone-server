const express = require('express');
const crypto = require("crypto");
const fs = require('fs');
const net = require('net');
require("dotenv").config();
let mysql = require("mysql");

const app = express();
app.use(express.json());

let connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});
connection.connect(function(err) {
    if (err) {
        return console.error('error: ' + err.message);
    }
    console.log("Connected to MYSQL database");
});

app.post('/login', async (req, res) => {
    // Decrypting message from user
    const prviateKey = fs.readFileSync(__dirname + "/pem/private.pem");
    const decryptedData = crypto.privateDecrypt({ key: prviateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(req.body[0], 'base64'));
    const data = JSON.parse(decryptedData.toString('utf-8'));

    console.log();
    console.log("Received request from user...");

    var recdValid = data[0];
    var recdUsername = data[1];
    var recdPassword = data[2];
    var nodeID = data[3];
    var recdKey = Buffer.from(data[4], 'base64');

    if(recdValid != "valid") {
        console.log("Invalid message");
        res.sendStatus(401);
        return;
    }

    // Authenticating user
    var queryRes = await new Promise((result) => 
        connection.query(`SELECT username FROM users_tab WHERE username="${recdUsername}" AND password="${recdPassword}"`, 
        (err,res)=> {
            if(err){
                console.log(err);
            }
            result(res)
        }));
    
    if (queryRes.length==0){
        console.log("Invalid login credentials");
        if (!res.headersSent)
            res.sendStatus(401);
        return;
    }

    // Get data about the requested node
    queryRes = await new Promise((result) => 
        connection.query(`SELECT node_ip, aes_key, next_iv FROM nodes_tab WHERE node_id="${nodeID}"`, 
        (err,res)=> {
            if(err){
                console.log(err);
            }
            result(res)
        }));

    if(queryRes.length==0) {
        console.log("Invalid node id");
        if (!res.headersSent)
            res.sendStatus(403);
        return;
    }

    var nodeIP = queryRes[0].node_ip;
    var key = queryRes[0].aes_key;
    var nextIV = queryRes[0].next_iv;

    // Update next IV in database for the required node
    queryRes = await new Promise((result) => 
        connection.query(`UPDATE nodes_tab SET next_iv=${nextIV+1} WHERE node_id="${nodeID}"`, 
        (err,res)=> {
            if(err){
                console.log(err);
            }
            result(res)
        }));    

    // Connect to the node
    var client = new net.Socket();
    client.connect(50000, nodeIP, function () {
        console.log('Node connected : ' + nodeIP + ':' + 50000);

        // Request new key
        var nonce = Buffer.from(nextIV.toString().padStart(12, '0'), "utf-8");
        var cipher = crypto.createCipheriv('aes-128-gcm', key, nonce, { authTagLength: 16 });
        var nonceCiphertextTag = Buffer.concat([
            nonce,
            cipher.update("KEY" + fs.readFileSync(__dirname+"/pem/public-nodes.pem", {encoding: "utf-8"})),
            cipher.final(),
            cipher.getAuthTag()
        ]);

        client.write(nonceCiphertextTag);
    });
    client.on('error', function (err) {
        console.log("Cannot connect to node");
        res.sendStatus(400);
    });
    client.on('data', function (data) {
        dataFromNode = Buffer.from(data, 'binary');

        const prviateKey = fs.readFileSync(__dirname + "/pem/private-nodes.pem");
        const decryptedData = crypto.privateDecrypt({ key: prviateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            dataFromNode);

        keyFromNode = decryptedData;

        process.stdout.write("Key from user : ");
        console.log(recdKey);
        process.stdout.write("Key from node : ");
        console.log(keyFromNode);

        xor = new Buffer.alloc(16);

        for (let i = 0; i < 16; i++) {
            xor[i] = recdKey[i] ^ keyFromNode[i];
        }

        process.stdout.write("Difference : ");
        console.log(xor);

        ret = JSON.stringify([nodeIP, xor.toString("base64")])

        console.log("Sending %s to the user.", ret);

        res.send(ret);

        client.destroy();
    });
    client.on('close', function () {
        console.log('Node connection closed');
        if (!res.headersSent) { // node closes connection without responding if authentitcation fails
            console.log("Authentication failed at node");
            res.sendStatus(418);
        }
    });
});

app.get('/key', (req, res) => {
    res.sendFile(__dirname + "/pem/public.pem");
});

app.get("/", (req, res) => {
    res.send("Running :)");
});

app.listen(3000, () => {
    console.log(`Server listening on port ${3000}`);
});