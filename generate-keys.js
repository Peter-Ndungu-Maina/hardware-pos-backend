const crypto = require('crypto');
const fs = require('fs');

console.log("Generating 2048-bit RSA keys...");

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    }
});

fs.writeFileSync('jenga-public.pem', publicKey);
fs.writeFileSync('jenga-private.pem', privateKey);

console.log("✅ Success! jenga-public.pem and jenga-private.pem have been created.");