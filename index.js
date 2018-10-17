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
const host = process.argv[3] || 'evote-server.skripsi.local:3443';

// SSL keys
const options = {
  url : 'https://' + host,
  key : fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/DPTClientApp/dpt_client_app.key'),
  cert : fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/DPTClientApp/dpt_client_app.pem'),
  ca : fs.readFileSync('../sawtooth-evote-ejbca/CA/KPUIntermediateCA-chain.pem'),
  passphrase : '123456',
}

prompt.start();
const schema = {
  properties : {
    cert : {
      message : 'Cert path',
      required : true,
      default : '../sawtooth-evote-ejbca/Dukcapil_DPT/52710501019120001_herpiko_dwi_aguno.pem'
    },
    key : {
      message : 'Key path',
      required : true,
      default : '../sawtooth-evote-ejbca/Dukcapil_DPT/52710501019120001_herpiko_dwi_aguno.plain.key'
    },
  }
}

prompt.get(schema, (err, result) => {
  var commonName;
  const voterCertPem = fs.readFileSync(result.cert, 'utf8');
  const voterCert = pki.certificateFromPem(voterCertPem);
  const voterKeyPem = fs.readFileSync(result.key, 'utf8');
  const voterKey = pki.privateKeyFromPem(voterKeyPem);

  console.log("\nVOTER IDENTITY on " + result.cert);
  console.log("==================================================");
  for (var i in voterCert.subject.attributes) {
    console.log((voterCert.subject.attributes[i].name || voterCert.subject.attributes[i].type) + ' : ' + voterCert.subject.attributes[i].value);
    if (voterCert.subject.attributes[i].name === 'commonName') {
      commonName = voterCert.subject.attributes[i].value;
    }
  }
  console.log("==================================================\n");
  if (!commonName) {
    console.log('Invalid commonName, please inspect the cert.');
    return;
  }

  // Verify eKTP cert
  const rootCA = pki.certificateFromPem(fs.readFileSync('../sawtooth-evote-ejbca/CA/KominfoRootCA.pem', 'utf8'));
  const dukcapilCA = pki.certificateFromPem(fs.readFileSync('../sawtooth-evote-ejbca/CA/DukcapilIntermediateCA.pem', 'utf8'));
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
  let spawned = spawnSync('openssl', ['verify',  '-crl_check', '-CAfile', '../sawtooth-evote-ejbca/CA/DukcapilIntermediateCA-crl-chain.pem', result.cert]);
  let crlCheckResult = spawned.stdout.toString().indexOf('OK') > -1
  console.log(crlCheckResult ? '- Verified\n' : '- Not verified / revoked');
  if (!crlCheckResult) return;

  const familyName = 'provinceDPT';
  const nameHash = createHash('sha256').update(commonName).digest('hex')
  const payloadNameHash = createHash('sha512').update(nameHash).digest('hex');
  const familyNameHash = createHash('sha512').update(familyName).digest('hex');
  const stateId = familyNameHash.substr(0, 6) + payloadNameHash.substr(-64);
  console.log('stateId : ' + stateId);
  console.log('action : ' + action);
  switch(action) {
    case 'activate' : 
      console.log('Activating...');
      // Generate unique random
      const u = createHash('sha256').update((new Date()).valueOf().toString()).digest('hex').substr(0, 16);
      const x = pbkdf2.pbkdf2Sync(u, commonName, 1, 32, 'sha512').toString('base64');
      let opt = Object.assign(options, {});
      opt.form = {r : x, voterId : commonName }
      request.post('https://' + host + '/api/activate', opt, (err, response) => {
        if (err) return console.log(err);
        let body = JSON.parse(response.body);
        if (body.status !== 'READY') {
          console.log(body);
          return;
        }
        const k = u + body.signedKey;
        console.log('\n\nThis KDF (k) is stored in smartcard and smartphone : \n\n' + k);
        const idv = pbkdf2.pbkdf2Sync(k, commonName, 1, 32, 'sha512').toString('base64') + k.substr(45);
        console.log('\n\nYour idv value : \n\n' + idv);
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
      const b = pbkdf2.pbkdf2Sync(k, commonName, 1, 32, 'sha512').toString('base64');
      const idv = b + k.substr(45);
      console.log('\nYour idv value : \n\n' + idv);
      return
    case 'state' :
      console.log('Checking state...');
      request.get('https://' + host + '/api/dpt-state/' + stateId, options, (err, response) => {
        if (err) return console.log(err);
        try {
          let body = JSON.parse(response.body);
          console.log('Current state : ' + body[Object.keys(body)[0]].toUpperCase());
        } catch(e) {
          console.log(response.body);
        }
      });
  }

});
