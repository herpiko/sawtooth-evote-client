const fs = require('fs');
const prompt = require('prompt');
const {createHash} = require('crypto')
const {spawnSync} = require('child_process');
const forge = require('node-forge');
const pki = forge.pki;
const base64 = require('js-base64').Base64;

const action = process.argv[2];
if (!action) throw('No action specified.');


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

});
