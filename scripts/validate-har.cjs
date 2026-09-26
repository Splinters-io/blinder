// Local schema compatibility check; never uploads captures. Install the pinned
// validator separately and pass its module directory via BLINDER_HAR_VALIDATOR.
const fs = require('node:fs');
const assert = require('node:assert/strict');

async function main() {
  const file = process.argv[2];
  const modulePath = process.env.BLINDER_HAR_VALIDATOR;
  if (!file || !modulePath) throw new Error('Usage: BLINDER_HAR_VALIDATOR=/path/to/har-validator node scripts/validate-har.cjs capture.har [--fixture]');
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  await require(modulePath).har(data);
  // Independent semantic checks on our synthetic fixture, beyond schema shape.
  const entries = new Map(data.log.entries.map(e => [new URL(e.request.url).pathname, e]));
  if (process.argv.includes('--fixture')) {
    assert.equal(data.log.entries.length, 7);
    const binary = entries.get('/binary');
    assert.equal(binary.request.postData._encoding, 'base64');
    assert.deepEqual(Buffer.from(binary.request.postData.text, 'base64'), Buffer.from([0, 255, 1]));
    assert.equal(binary.response.content.encoding, 'base64');
    assert.deepEqual(Buffer.from(binary.response.content.text, 'base64'), Buffer.from([0, 255, 2]));
    assert.equal(entries.get('/partial').response.status, 503);
    assert.equal(entries.get('/partial').response.content.text, 'partial diagnostic');
    assert.equal(entries.get('/transport').response.status, 0);
    assert.equal(entries.get('/transport').response.content.size, 0);
    assert.equal(entries.get('/redirect').response.redirectURL, 'https://fixture.invalid/destination');
    assert.equal(entries.get('/socket').response.status, 101);
  }
  console.log(`HAR schema accepted ${data.log.entries.length} entries${process.argv.includes('--fixture') ? '; synthetic semantic checks passed' : ''}.`);
}
main().catch(error => {
  console.error(JSON.stringify(error.errors || {message:error.message}, null, 2));
  process.exitCode = 1;
});
