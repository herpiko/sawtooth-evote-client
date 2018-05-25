const fs = require('fs');
const qr = require('qr-image');
const prompt = require('prompt');
const {createHash} = require('crypto')
const {spawnSync} = require('child_process');
const execSync = require('child_process').execSync;
const forge = require('node-forge');
const pki = forge.pki;
const base64 = require('js-base64').Base64;
const request = require('request');
const pbkdf2 = require('pbkdf2');

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
  console.log('action : ' + action);
  switch(action) {
    case 'activate' : 
      console.log('activating');
      // Generate unique random
      const u = createHash('sha256').update((new Date()).valueOf().toString()).digest('hex').substr(0, 16);
      const x = pbkdf2.pbkdf2Sync(u, UID, 1, 32, 'sha512').toString('base64');

      request.post('http://' + host + '/api/activate', {form : {r : x, voterId : UID }}, (err, response) => {
        if (err) return console.log(err);
        let body = JSON.parse(response.body);
        if (body.status !== 'READY') {
          console.log(body);
          return;
        }
        const k = u + body.signedKey;
        console.log('This KDF is stored in smartcard and smartphone : \n' + k);
        const idv = pbkdf2.pbkdf2Sync(k, UID, 1, 32, 'sha512').toString('base64') + k.substr(45);
        console.log('Your idv value : \n' + idv);
        let filename = createHash('sha512').update((new Date()).valueOf().toString()).digest('hex').toString() + '.png';
        var qr_svg = qr.image(k, { type: 'png' });
        qr_svg.pipe(require('fs').createWriteStream(filename));
        setTimeout(() => {
          execSync(`/usr/bin/feh ${__dirname}/${filename}`);
        }, 500);
      });
      return;
    case 'idv' :
      if (!process.argv[3]) {
        console.log('Please provide a k value, ex : node index.js idv kvaluestring');
        return;
      }
      const k = process.argv[3];
      if (k.length !== 148) {
        console.log('Invalid k value, should be 148 length');
        return;
      }
      const b = pbkdf2.pbkdf2Sync(k, UID, 1, 32, 'sha512').toString('base64');
      const idv = b + k.substr(45);
      console.log('Your idv value : \n' + idv);
      return
    case 'state' :
      request.get('http://' + host + '/api/dpt-state/' + stateId, (err, response) => {
        if (err) return console.log(err);
        let body = JSON.parse(response.body);
        console.log('Current state : ' + body[Object.keys(body)[0]].toUpperCase());
      });
  }

});
