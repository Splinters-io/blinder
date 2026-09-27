const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const sent = [], opened = [];
function ScriptElement() {}
Object.defineProperty(ScriptElement.prototype, 'src', {
  configurable: true, enumerable: true,
  get() { return this.nativeSource; }, set(value) { this.nativeSource = value; }
});
function Element() {}
Element.prototype.setAttribute = function(name, value) { this[name] = value; };
function XHR() {}
XHR.prototype.open = function(...values) { opened.push(values); };
const document = {baseURI: 'https://captcha-fixture.localhost:8099/widget/frame?stage=one'};
const context = vm.createContext({URL, Request, XMLHttpRequest: XHR, Element, document,
  cfg: {base: 'https://provider.example/widget/frame?stage=one', aliases: {
    'https://provider.example': 'https://captcha-fixture.localhost:8099',
    'https://ports.example:444': 'https://captcha-default.localhost'
  }},
  window: {HTMLScriptElement: ScriptElement, fetch: async (input, init) => { sent.push({input, init}); return 'native'; }}
});
vm.runInContext(fs.readFileSync('provider_runtime.js', 'utf8'), context);
const route = value => vm.runInContext('route(' + JSON.stringify(value) + ')', context);
assert.equal(route('https://provider.example/widget/api?x=1&x=2#f'), 'https://captcha-fixture.localhost:8099/widget/api?x=1&x=2#f');
assert.equal(route('//provider.example/widget/frame'), 'https://captcha-fixture.localhost:8099/widget/frame');
assert.equal(route('https://ports.example:444/widget/api'), 'https://captcha-default.localhost/widget/api');
for (const value of ['relative?x=1', '#fragment', 'https://unknown.example/x', 'http://provider.example/x',
  'https://provider.example:444/x', 'https://user:pass@provider.example/x', 'data:text/plain,fixture']) {
  assert.equal(route(value), value);
}
const script = new ScriptElement();
script.src = 'https://provider.example/widget/dynamic.js';
assert.equal(script.src, 'https://captcha-fixture.localhost:8099/widget/dynamic.js');
const element = new Element();
element.setAttribute('src', 'https://provider.example/widget/inner');
assert.equal(element.src, 'https://captcha-fixture.localhost:8099/widget/inner');
element.setAttribute('integrity', 'sha384-original');
assert.equal(element.integrity, 'sha384-original');
new XHR().open('vendor.sync', 'https://provider.example/widget/status', true, 'user', 'password');
assert.deepEqual(opened[0], ['vendor.sync', 'https://captcha-fixture.localhost:8099/widget/status', true, 'user', 'password']);
(async () => {
  const abort = new AbortController();
  const request = new Request('https://provider.example/widget/api?x=1&x=2', {
    method: 'vendor.sync', body: '{"opaque":"exact"}', headers: {'Content-Type': 'application/json', 'X-Token': 'original'},
    credentials: 'include', mode: 'cors', cache: 'no-store', redirect: 'manual', integrity: 'sha384-original',
    referrer: 'https://provider.example/widget/frame', referrerPolicy: 'no-referrer', signal: abort.signal
  });
  assert.equal(await context.window.fetch(request), 'native');
  const mapped = sent[0].input;
  assert.equal(mapped.url, 'https://captcha-fixture.localhost:8099/widget/api?x=1&x=2');
  for (const key of ['method', 'credentials', 'mode', 'cache', 'redirect', 'integrity', 'referrer', 'referrerPolicy']) {
    assert.equal(mapped[key], request[key], key);
  }
  assert.equal(mapped.headers.get('X-Token'), 'original');
  assert.equal(await mapped.text(), '{"opaque":"exact"}');
  abort.abort();
  assert.equal(mapped.signal.aborted, true);
  const unknown = new Request('https://unknown.example/widget/api');
  await context.window.fetch(unknown);
  assert.equal(sent[1].input, unknown);
  await context.window.fetch('https://provider.example/widget/api', {method: 'PUT', body: 'new body', credentials: 'omit'});
  assert.equal(sent[2].input.method, 'PUT');
  assert.equal(sent[2].input.credentials, 'omit');
  assert.equal(await sent[2].input.text(), 'new body');
  const stream = new ReadableStream({start(controller) {
    controller.enqueue(new TextEncoder().encode('first-'));
    controller.enqueue(new TextEncoder().encode('second'));
    controller.close();
  }});
  const streaming = new Request('https://provider.example/widget/stream', {method: 'PATCH', body: stream, duplex: 'half'});
  await context.window.fetch(streaming);
  assert.equal(sent[3].input.method, 'PATCH');
  assert.equal(await sent[3].input.text(), 'first-second');
})().catch(error => { console.error(error); process.exitCode = 1; });
