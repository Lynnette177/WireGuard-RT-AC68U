// Exercises the real page's Web Crypto submission with synthetic credentials.
const fs = require('fs');
const vm = require('vm');
const { generateKeyPairSync, privateDecrypt, constants, webcrypto } = require('crypto');
const { TextEncoder } = require('util');

const page = fs.readFileSync('campus/page.asp', 'utf8');
const match = page.match(/<script>\s*([\s\S]*?)<\/script>/);
if (!match) throw new Error('page script missing');
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const script = match[1].replace('<% get_custom_settings(); %>', '{}').replace('__CAMPUS_PUBLIC_KEY__', publicKey);
const fields = {};
for (const id of ['enabled', 'interval', 'username', 'password', 'error', 'amng_custom', 'status', 'campus-form']) fields[id] = { value: '', textContent: '', checked: false };
fields.enabled.checked = true;
fields.interval.value = '7';
fields.username.value = 'synthetic-user';
fields.password.value = 'synthetic-password';
let submissions = 0;
fields['campus-form'].submit = () => { submissions++; };
const context = {
  window: { crypto: webcrypto }, crypto: webcrypto, TextEncoder, Uint8Array,
  document: { getElementById: id => fields[id] },
  location: { protocol: 'https:', pathname: '/user1.asp' },
  atob: value => Buffer.from(value, 'base64').toString('binary'),
  btoa: value => Buffer.from(value, 'binary').toString('base64'),
  setTimeout: () => 0, setInterval: () => 0,
};
vm.createContext(context);
vm.runInContext(script, context);
(async () => {
  await context.campusSave();
  if (submissions !== 1) throw new Error('valid settings were not submitted');
  const submitted = fields.amng_custom.value;
  if (submitted.includes('synthetic-user') || submitted.includes('synthetic-password')) throw new Error('plaintext credentials leaked into form');
  const data = JSON.parse(submitted);
  const plaintext = privateDecrypt({ key: pair.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(data.campuslogin_secret, 'base64'));
  const credentials = JSON.parse(plaintext.toString('utf8'));
  if (credentials.username !== 'synthetic-user' || credentials.password !== 'synthetic-password') throw new Error('encrypted credentials differ');
  if (fields.username.value || fields.password.value) throw new Error('credentials remain in page inputs');
  fields.interval.value = '9';
  await context.campusSave();
  if (submissions !== 2 || JSON.parse(fields.amng_custom.value).campuslogin_secret !== data.campuslogin_secret) throw new Error('credential update was not retained on second submit');
  context.location.protocol = 'http:';
  fields.username.value = 'http-user';
  fields.password.value = 'http-password';
  await context.campusSave();
  if (submissions !== 3) throw new Error('HTTP submission failed');
  const httpData = JSON.parse(fields.amng_custom.value);
  const httpPlain = privateDecrypt({ key: pair.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(httpData.campuslogin_secret, 'base64'));
  if (JSON.parse(httpPlain.toString('utf8')).password !== 'http-password') throw new Error('HTTP encrypted credentials differ');
  console.log('RSA-OAEP submission over HTTP and HTTPS, and repeat save verified.');
})().catch(error => { console.error(error.message); process.exit(1); });
