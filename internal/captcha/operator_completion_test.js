// Exercise controller transitions without provider SDKs or external traffic.
// The browser acceptance fixture covers real navigation and cookie auth.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync('operator_completion.js', 'utf8');

function setup(automatic, value = '') {
  const state = {submissions: [], observers: [], timers: [], windowEvents: {}, throwNext: false};
  class Element {
    constructor(tag) {
      this.tag = tag; this.children = []; this.attributes = {}; this.events = {};
      this.value = ''; this.name = ''; this.type = ''; this.hidden = false;
      this.disabled = false; this.textContent = '';
    }
    setAttribute(name, value) { this.attributes[name] = value; }
    removeAttribute(name) { delete this.attributes[name]; }
    append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
    insertAdjacentElement(position, element) { this.parent.append(element); }
    addEventListener(name, fn) { (this.events[name] ||= []).push(fn); }
    querySelectorAll() { return this.children.filter(child => child.type === 'submit'); }
    get elements() { return this.children; }
  }
  class Form extends Element {
    constructor() { super('form'); }
    submit() {
      state.submissions.push(this);
      if (state.throwNext) { state.throwNext = false; throw new Error('synthetic navigation error'); }
    }
  }
  const field = new Element('input'); field.name = 'fixture-response'; field.value = value;
  const button = new Element('button'); button.type = 'submit';
  const form = new Form(); form.append(field, button);
  form.method = 'POST'; form.action = '/__blinder/captcha/challenge/fixture-session';
  const frame = {contentWindow: {}};
  const body = new Element('body');
  body.append(form);
  function descendants(node) { return node.children.flatMap(child => [child, ...descendants(child)]); }
  const document = {
    body,
    createElement(tag) { return tag === 'form' ? new Form() : new Element(tag); },
    querySelector(selector) { return selector === 'iframe' ? frame : form; },
    querySelectorAll() { return descendants(body).filter(element => ['input', 'textarea'].includes(element.tag) && element.name); }
  };
  const window = {addEventListener(name, fn) { (state.windowEvents[name] ||= []).push(fn); }};
  class Observer {
    constructor(callback) { this.callback = callback; state.observers.push(this); }
    observe() { this.active = true; }
    disconnect() { this.active = false; }
  }
  const setInterval = callback => { const timer = {callback, active: true}; state.timers.push(timer); return timer; };
  const clearInterval = timer => { if (timer) timer.active = false; };
  new Function('c', 'document', 'window', 'MutationObserver', 'HTMLFormElement', 'setInterval', 'clearInterval', source)(
    {session: 'fixture-session', fields: ['fixture-response'], automatic, origin: 'https://fixture.blinder-challenge.localhost'}, document, window, Observer, Form, setInterval, clearInterval);
  const fire = (target, name, event = {}) => {
    event.preventDefault = () => { event.prevented = true; };
    for (const fn of target.events[name] || []) fn(event);
    return event;
  };
  const windowEvent = (name, event) => { for (const fn of state.windowEvents[name] || []) fn(event); };
  const status = () => descendants(body).find(element => element.attributes.role === 'status');
  const retry = () => descendants(body).find(element => element.tag === 'button' && element.type === 'button');
  return {state, field, form, button, frame, body, fire, windowEvent, status, retry};
}

{
  const h = setup(false);
  const message = {source: h.frame.contentWindow, origin: 'https://fixture.blinder-challenge.localhost', data: {type: 'blinder-fields', session: 'fixture-session', fields: {'fixture-response': 'solved'}}};
  h.windowEvent('message', {...message, source: {}});
  assert.equal(h.field.value, '', 'untrusted frame filled the form');
  h.windowEvent('message', message);
  assert.equal(h.field.value, 'solved');
  assert.equal(h.fire(h.form, 'submit').prevented, true, 'default submission must be explicitly replaced');
  assert.equal(h.state.submissions.length, 1, 'manual submission never invoked native form navigation');
  assert.equal(h.state.submissions[0], h.form, 'native submission must use the trusted outer form');
  assert.equal(h.button.disabled, true);
  assert.equal(h.status().textContent, 'Submitting solution…');
  assert.equal(h.fire(h.form, 'submit').prevented, true, 'duplicate native submission allowed');
  assert.equal(h.state.submissions.length, 1, 'duplicate event initiated a second navigation');
  message.data.fields['fixture-response'] = 'changed-during-submission';
  h.windowEvent('message', message);
  assert.equal(h.field.value, 'solved', 'pending submission fields changed');
  h.windowEvent('pageshow', {persisted: true});
  assert.equal(h.button.disabled, false, 'back navigation left retry disabled');
  assert.equal(h.fire(h.form, 'submit').prevented, true, 'retry must explicitly replace default submission');
  assert.equal(h.state.submissions.length, 2, 'explicit retry did not initiate native navigation');
}

{
  const h = setup(true);
  const message = {source: h.frame.contentWindow, origin: 'https://fixture.blinder-challenge.localhost', data: {type: 'blinder-fields', session: 'fixture-session', fields: {'fixture-response': 'solved'}}};
  assert.equal(h.state.submissions.length, 0);
  h.windowEvent('message', {...message, source: {}});
  h.windowEvent('message', {...message, origin: 'null'});
  h.windowEvent('message', {...message, origin: 'https://other.blinder-challenge.localhost'});
  h.windowEvent('message', {...message, origin: 'https://fixture.blinder-challenge.localhost:8099'});
  h.windowEvent('message', {...message, data: {...message.data, session: 'other-session'}});
  h.windowEvent('message', {...message, data: {...message.data, fields: {'unconfigured-response': 'solved'}}});
  assert.equal(h.field.value, '', 'foreign origin/session/unconfigured fields modified the trusted form');
  assert.equal(h.state.submissions.length, 0, 'untrusted window/session submitted automatically');
  h.windowEvent('message', message);
  assert.equal(h.state.submissions.length, 1);
  const submitted = h.state.submissions[0];
  assert.equal(submitted, h.form, 'submission must use trusted outer form');
  assert.equal(submitted.method, 'POST');
  assert.equal(submitted.action, '/__blinder/captcha/challenge/fixture-session');
  assert.equal(h.field.value, 'solved');
  assert.equal(h.status().textContent, 'Submitting solution…');
  assert.equal(h.state.timers.length, 0, 'trusted wrapper must not poll challenge DOM');
  assert.equal(h.state.observers.length, 0);
  h.windowEvent('message', message);
  assert.equal(h.state.submissions.length, 1, 'repeated provider message resubmitted');
  h.windowEvent('pageshow', {persisted: true});
  assert.equal(h.button.disabled, false);
  h.windowEvent('message', message);
  assert.equal(h.state.submissions.length, 1, 'back navigation restarted automatic submission');
  assert.equal(h.fire(h.form, 'submit').prevented, true, 'retry must explicitly replace default submission');
  assert.equal(h.state.submissions.length, 2, 'explicit retry did not initiate native navigation');
}

{
  const h = setup(true);
  const message = {source: h.frame.contentWindow, origin: 'https://fixture.blinder-challenge.localhost', data: {type: 'blinder-fields', session: 'fixture-session', fields: {'fixture-response': 'solved'}}};
  h.state.throwNext = true;
  h.windowEvent('message', message);
  assert.match(h.status().textContent, /could not start/);
  assert.equal(h.button.disabled, false);
  h.windowEvent('message', message);
  assert.equal(h.state.submissions.length, 1, 'failed navigation entered an automatic retry loop');
  assert.equal(h.fire(h.form, 'submit').prevented, true, 'manual retry did not own default submission');
  assert.equal(h.state.submissions.length, 2, 'manual retry did not invoke native navigation');
}
assert.doesNotMatch(source, /\bfetch\s*\(/, 'completion must preserve native-navigation authorization');
assert.doesNotMatch(source, /Solution submitted/, 'client must not invent a successful receipt');
console.log('Operator completion transitions passed.');
