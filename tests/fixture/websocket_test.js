'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, 'websocket.js'), 'utf8');

for (const protocol of ['https:', 'http:']) {
  const listeners = {};
  const elements = {live: {textContent: ''}, 'socket-state': {textContent: ''}};
  const sockets = [];
  class Socket {
    static CLOSING = 2;
    constructor(url) { this.url = url; this.readyState = 0; this.closes = []; sockets.push(this); }
    close(code, reason) { this.closes.push([code, reason]); this.readyState = 2; }
  }
  vm.runInNewContext(source, {
    WebSocket: Socket,
    location: {protocol, host: '127.0.0.1:18099'},
    document: {getElementById: id => elements[id]},
    window: {addEventListener: (name, fn) => { listeners[name] = fn; }},
  });
  const status = elements['socket-state'];
  assert.equal(sockets.length, 1);
  assert.equal(sockets[0].url, (protocol === 'https:' ? 'wss:' : 'ws:') + '//127.0.0.1:18099/ws');
  listeners.pageshow({persisted: false});
  assert.equal(sockets.length, 1, 'initial pageshow must not duplicate the connection');
  let previous = sockets[0];
  for (let cycle = 1; cycle <= 3; cycle++) {
    previous.readyState = 1;
    previous.onopen();
    previous.onmessage({data: 'live-' + cycle});
    listeners.pagehide({persisted: true});
    assert.deepEqual(previous.closes, [[1000, 'page hidden']]);
    listeners.pageshow({persisted: true});
    assert.equal(sockets.length, cycle + 1, 'restore must create exactly one connection');
    const current = sockets.at(-1);
    current.readyState = 1;
    current.onopen();
    current.onmessage({data: 'restored-' + cycle});
    previous.onerror();
    previous.onclose({code: 1006});
    previous.onmessage({data: 'stale'});
    assert.equal(elements.live.textContent, 'restored-' + cycle);
    assert.equal(status.textContent, 'WebSocket connected; history restores: ' + cycle);
    previous = current;
  }
  previous.onerror();
  assert.equal(status.textContent, 'WebSocket failed', 'active errors remain visible');
  previous.onclose({code: 1006});
  assert.equal(status.textContent, 'WebSocket closed (code 1006)');
  listeners.pagehide({persisted: false});
  assert.equal(sockets.length, 4, 'leaving the page must not reconnect');
}
console.log('WebSocket navigation lifecycle passed for HTTP and HTTPS');
