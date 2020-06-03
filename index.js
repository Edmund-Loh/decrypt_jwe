const jose = require('node-jose');
const jwtDecode = require('jwt-decode');
const dotenv = require('dotenv');
dotenv.config();

//input_key as a JWK
const input_key = {
    p: process.env.p,
    kty: process.env.kty,
    q: process.env.q,
    d: process.env.d,
    e: process.env.e,
    kid: process.env.kid,
    qi: process.env.qi,
    dp: process.env.dp,
    dq: process.env.dq,
    n: process.env.n,
    use: process.env.use,
    alg: process.env.alg,
};

//input the JWE object here
const encrypted_id_token = process.env.encrypted_id_token;

//create a keystore
var keystore = jose.JWK.createKeyStore();

async function decryptJwe(jweObject) {
    // add RSA key to keystore
    await keystore.add(input_key).then(

        // input_key is either a:
        // *  jose.JWK.Key to copy from; or
        // *  JSON object representing a JWK; or

        function(result) {
            // {result} is a jose.JWK.Key
            return result;
        }
    );
    
    // get the key that was added
    const key = keystore.get(input_key.kid);
    
    // print the decrypted id token in base64url encoding and as a JSON object
    jose.JWE.createDecrypt(key).decrypt(jweObject).then(
        function(result) {
            const plaintext = result.plaintext.toString();
            const payload = result.payload.toString();
            
            console.log(plaintext);
            console.log("\n");
            console.log(jwtDecode(plaintext));
            console.log("\n");
            console.log(payload);
            console.log("\n");
            console.log(jwtDecode(payload));
        }
    );
}

decryptJwe(encrypted_id_token);