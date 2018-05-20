const fs = require('fs');
const prompt = require('prompt');
const {createHash} = require('crypto')
const {spawnSync} = require('child_process');
const forge = require('node-forge');
const pki = forge.pki;
const base64 = require('js-base64').Base64;
const request = require('request');

const action = process.argv[2];
if (!action) throw('No action specified. Ex : node index operation host:port');
const host = process.argv[3] || 'localhost:3000';

prompt.start();
const schema = {
  properties : {
    cert : {
      message : 'Cert path',
      required : true,
      default : 'certs/dpt/herpiko_52710501019120001.pem'
    },
    key : {
      message : 'Key path',
      required : true,
      default : 'certs/dpt/herpiko_52710501019120001.plain.key'
    },
  }
}

prompt.get(schema, (err, result) => {
  var UID;
  const voterCertPem = fs.readFileSync(result.cert, 'utf8');
  const voterCert = pki.certificateFromPem(voterCertPem);
  const voterKeyPem = fs.readFileSync(result.key, 'utf8');
  const voterKey = pki.privateKeyFromPem(voterKeyPem);

  console.log("\nVOTER IDENTITY on " + result.cert);
  console.log("=====================================");
  for (var i in voterCert.subject.attributes) {
    console.log((voterCert.subject.attributes[i].name || voterCert.subject.attributes[i].type) + ' : ' + voterCert.subject.attributes[i].value);
    if (voterCert.subject.attributes[i].type === '0.9.2342.19200300.100.1.1') {
      UID = voterCert.subject.attributes[i].value;
    }
  }
  console.log("=====================================\n");

  // Verify eKTP cert
  const rootCA = pki.certificateFromPem(fs.readFileSync('certs/ca/KominfoRootCA.pem', 'utf8'));
  const dukcapilCA = pki.certificateFromPem(fs.readFileSync('certs/ca/DukcapilIntermediateCA.pem', 'utf8'));
  console.log('Verifying cert against CA...');
  try {
    const verified = dukcapilCA.verify(voterCert)
    console.log('- Verified');
  } catch (e) {
    console.log('\nError : eKTP is not verified');
    return;
  }

  // Verify against CRL
  console.log('Verifying cert against CRL...');
  let spawned = spawnSync('openssl', ['verify',  '-crl_check', '-CAfile', 'certs/ca/DukcapilIntermediateCA.crl-chain.pem', result.cert]);
  let crlCheckResult = spawned.stdout.toString().indexOf('OK') > -1
  console.log(crlCheckResult ? '- Verified\n' : '- Not verified / revoked');
  if (!crlCheckResult) return;

  const familyName = 'provinceDPT';
  const payloadNameHash = createHash('sha512').update(createHash('sha256').update(UID).digest('hex')).digest('hex');
  const familyNameHash = createHash('sha512').update(familyName).digest('hex');
  const stateId = familyNameHash.substr(0, 6) + payloadNameHash.substr(-64);
  console.log('stateId : ' + stateId);

  switch(action) {
    case 'register' : 
      // Generate unique random
      const u = createHash('sha256').update((new Date()).valueOf().toString()).digest('hex').substr(0, 16);
      request.post('http://' + host + '/api/register', {form : {r : u, voterId : UID }}, (err, response) => {
        if (err) return console.log(err);
        console.log(response.body);
      });
    case 'state' :
      request.get('http://' + host + '/api/dpt-state/' + stateId, (err, response) => {
        if (err) return console.log(err);
        let body = JSON.parse(response.body);
        console.log('Current state : ' + body[Object.keys(body)[0]].toUpperCase());
      });
  }

});
