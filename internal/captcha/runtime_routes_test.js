const vm=require('node:vm');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const sent=[];
const context=vm.createContext({URL,Request,
  cfg:{endpoint:'https://blinder-operator.localhost:8099/__blinder/captcha/res',base:'https://provider.example/v1/',session:'fixture-session',origins:['https://provider.example'],aliases:{'https://provider.example':'https://captcha-fixture.localhost:8099'},fields:[]},
  window:{fetch:async(input,init)=>{sent.push({input,init});return {};},addEventListener(){},parent:{postMessage(){}}},
  XMLHttpRequest:function(){},Element:function(){},
  document:{addEventListener(){},querySelectorAll(){return [];}},setInterval(){},clearInterval(){},
});
context.XMLHttpRequest.prototype.open=function(){};
context.Element.prototype.setAttribute=function(){};
vm.runInContext(fs.readFileSync('runtime.js','utf8'),context);
const route=value=>vm.runInContext('route('+JSON.stringify(value)+')',context);
assert.equal(route('https://provider.example/v1/api?q=1&q=2#f'),'https://captcha-fixture.localhost:8099/v1/api?q=1&q=2#f');
assert.equal(route('https://blinder-operator.localhost:8099/v1/api?q=1&q=2'),'https://captcha-fixture.localhost:8099/v1/api?q=1&q=2');
assert.equal(route('https://unrelated.example/api'),'https://unrelated.example/api');
assert.equal(route('https://captcha-fixture.localhost:8099/v1/api'),'https://captcha-fixture.localhost:8099/v1/api');
assert.equal(vm.runInContext('original("https://captcha-fixture.localhost:8099/v1/api?q=1&q=2")',context),'https://provider.example/v1/api?q=1&q=2');
(async()=>{
  await context.window.fetch('https://provider.example/v1/api',{credentials:'include',cache:'no-cache'});
  assert.equal(sent[0].input,'https://captcha-fixture.localhost:8099/v1/api');
  assert.equal(sent[0].init.credentials,'include');
  assert.equal(sent[0].init.cache,'no-cache');
  assert.ok(!sent[0].input.includes('sid='));
})().catch(e=>{console.error(e);process.exitCode=1});
