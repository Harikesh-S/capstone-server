const crypto = require('crypto');
const fs = require('fs');

const RSA = 'rsa';
let options = {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
    }
};

let keyCallbackUser = (err, publicKey, privateKey) => {
    if (!err) {
        console.log('\n');
        console.log(publicKey);
        console.log(privateKey);
        fs.writeFile('./pem/public.pem', publicKey, (err) => {
            if (err) throw err
        })
        fs.writeFile('./pem/private.pem', privateKey, (err) => {
            if (err) throw err
        })
    } else {
        throw err;
    }
};
let keyCallbackNodes = (err, publicKey, privateKey) => {
    if (!err) {
        console.log('\n');
        console.log(publicKey);
        console.log(privateKey);
        fs.writeFile('./pem/public-nodes.pem', publicKey, (err) => {
            if (err) throw err
        })
        fs.writeFile('./pem/private-nodes.pem', privateKey, (err) => {
            if (err) throw err
        })
    } else {
        throw err;
    }
};

crypto.generateKeyPair(RSA, options, keyCallbackUser);
crypto.generateKeyPair(RSA, options, keyCallbackNodes);