'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {exportHAR} = require('./export-playwright-har.cjs');

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blinder-har-export-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const input = path.join(dir, 'original.har');
  const output = path.join(dir, 'export');
  const requestBody = Buffer.from([0, 255, 1]);
  const responseBody = Buffer.from([0, 255, 2]);
  const har = {log: {version: '1.2', creator: {name: 'blinder', version: 'fixture'}, entries: [{
    startedDateTime: '2026-09-26T00:00:00Z', time: 10,
    request: {method: 'POST', url: 'https://fixture.invalid/binary', httpVersion: 'HTTP/1.1',
      headers: [{name: 'Content-Type', value: 'application/octet-stream'}], cookies: [], queryString: [],
      headersSize: -1, bodySize: 3,
      postData: {mimeType: 'application/octet-stream', text: requestBody.toString('base64'), _encoding: 'base64', comment: 'capture metadata'}},
    response: {status: 503, statusText: 'Fixture diagnostic', httpVersion: 'HTTP/1.1',
      headers: [{name: 'X-Diagnostic', value: 'first'}, {name: 'X-Diagnostic', value: 'second'}],
      cookies: [], redirectURL: '', headersSize: -1, bodySize: 3,
      content: {mimeType: 'application/octet-stream', size: 3, text: responseBody.toString('base64'), encoding: 'base64', comment: 'partial fixture'}},
    cache: {}, timings: {send: 0, wait: 10, receive: 0}, _fixtureMetadata: {sequence: 7}
  }]}};
  const original = JSON.stringify(har, null, 1) + '\n';
  fs.writeFileSync(input, original, {mode: 0o600});
  return {dir, input, output, har, original, requestBody, responseBody};
}

test('CLI writes private binary attachments, preserving source and other evidence', t => {
  const f = fixture(t);
  const run = spawnSync(process.execPath, [path.join(__dirname, 'export-playwright-har.cjs'), f.input, f.output], {encoding: 'utf8'});
  assert.equal(run.status, 0, run.stderr);
  assert.equal(JSON.parse(run.stdout).binaryRequestAttachments, 1);
  const exported = JSON.parse(fs.readFileSync(path.join(f.output, 'capture.har'), 'utf8'));
  const attachment = exported.log.entries[0].request.postData._file;
  assert.match(attachment, /^resources\/request-\d+\.bin$/);
  assert.deepEqual(fs.readFileSync(path.join(f.output, attachment)), f.requestBody);
  const expected = structuredClone(f.har);
  delete expected.log.entries[0].request.postData.text;
  delete expected.log.entries[0].request.postData._encoding;
  expected.log.entries[0].request.postData._file = attachment;
  assert.deepEqual(exported, expected);
  assert.equal(fs.readFileSync(f.input, 'utf8'), f.original);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(f.output).mode & 0o077, 0);
    assert.equal(fs.statSync(path.join(f.output, attachment)).mode & 0o077, 0);
    assert.equal(fs.statSync(path.join(f.output, 'capture.har')).mode & 0o077, 0);
  }
});

test('an existing output directory is never overwritten', t => {
  const f = fixture(t);
  fs.mkdirSync(f.output);
  fs.writeFileSync(path.join(f.output, 'capture.har'), 'keep existing evidence');
  assert.throws(() => exportHAR(f.input, f.output), {code: 'EEXIST'});
  assert.equal(fs.readFileSync(path.join(f.output, 'capture.har'), 'utf8'), 'keep existing evidence');
  assert.equal(fs.existsSync(path.join(f.output, 'resources')), false);
});

test('reject invalid binary data and existing external references before writing', t => {
  const f = fixture(t);
  for (const mutate of [
    har => { har.log.entries[0].request.postData.text = 'not valid base64!!'; },
    har => { har.log.entries[0].request.postData._encoding = 'unknown'; },
    har => { har.log.entries[0].request.postData._file = '../outside.bin'; },
    har => { har.log.entries[0].response.content._file = '/outside.bin'; },
  ]) {
    const bad = structuredClone(f.har);
    mutate(bad);
    fs.writeFileSync(f.input, JSON.stringify(bad));
    assert.throws(() => exportHAR(f.input, f.output));
    assert.equal(fs.existsSync(f.output), false);
  }
});

test('ordinary text requests and diagnostic status metadata are unchanged', t => {
  const f = fixture(t);
  delete f.har.log.entries[0].request.postData._encoding;
  f.har.log.entries[0].request.postData.text = '{"n":9007199254740993123,"n":-0}';
  f.har.log.entries[0].response.status = 0;
  f.har.log.entries[0].response.content.comment = 'transport failure';
  fs.writeFileSync(f.input, JSON.stringify(f.har));
  assert.equal(exportHAR(f.input, f.output).binaryRequestAttachments, 0);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.output, 'capture.har'))), f.har);
});

test('installed Playwright importer matches original binary POST bytes after export', {
  skip: !process.env.BLINDER_PLAYWRIGHT_MODULE && 'Set BLINDER_PLAYWRIGHT_MODULE to an existing Playwright module path',
}, async t => {
  const f = fixture(t);
  // Importer calls only; no browser, child process, or HTTP request is needed.
  const playwright = require(process.env.BLINDER_PLAYWRIGHT_MODULE);
  const utils = playwright._connection.localUtils();
  const original = await utils.harOpen({file: f.input});
  assert.ok(original.harId, original.error);
  const exportedPath = exportHAR(f.input, f.output).harPath;
  const converted = await utils.harOpen({file: exportedPath});
  assert.ok(converted.harId, converted.error);
  const lookup = (harId, postData) => utils.harLookup({
    harId, url: f.har.log.entries[0].request.url, method: 'POST', headers: [], postData, isNavigationRequest: false,
  });
  try {
    assert.equal((await lookup(original.harId, f.requestBody)).action, 'noentry');
    const actual = await lookup(converted.harId, f.requestBody);
    assert.equal(actual.action, 'fulfill');
    assert.equal(actual.status, 503);
    assert.deepEqual(actual.body, f.responseBody);
    assert.deepEqual(actual.headers, f.har.log.entries[0].response.headers);
    assert.equal((await lookup(converted.harId, Buffer.from(f.requestBody.toString('base64')))).action, 'noentry');
    assert.equal(fs.readFileSync(f.input, 'utf8'), f.original);
  } finally {
    await utils.harClose({harId: original.harId});
    await utils.harClose({harId: converted.harId});
  }
});
