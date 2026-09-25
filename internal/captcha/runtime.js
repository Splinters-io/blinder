// This runs only in a sandboxed operator/provider document, before provider code.
// The relay repeats all origin/URL scope checks; this mapping grants no access.
const endpoint = new URL(cfg.endpoint);
const base = new URL(cfg.base);
const origins = new Set((cfg.origins || []).map(value => new URL(value).origin));
function route(value) {
  if (typeof value !== 'string' || !value || value[0] === '#') return value;
  let target;
  try { target = new URL(value, base); } catch { return value; }
  if (target.origin === endpoint.origin && target.pathname === endpoint.pathname) return value;
  // Request objects and DOM URL properties may already have resolved against
  // the local document. Recover the original provider base for those references.
  if (target.origin === endpoint.origin && origins.has(base.origin)) {
    target = new URL(target.pathname + target.search + target.hash, base);
  }
  if (!origins.has(target.origin)) return value;
  const fragment = target.hash;
  target.hash = '';
  const local = new URL(endpoint);
  local.searchParams.set('u', target.href);
  local.searchParams.set('sid', cfg.session);
  local.hash = fragment;
  return local.href;
}
function original(value) {
  try {
    const u = new URL(value, endpoint);
    if (u.origin === endpoint.origin && u.pathname === endpoint.pathname && u.searchParams.has('u')) {
      return u.searchParams.get('u') + u.hash;
    }
  } catch {}
  return value;
}
const nativeFetch = window.fetch.bind(window);
window.fetch = function(input, init) {
  const raw = input instanceof Request ? input.url : String(input);
  const mapped = route(raw);
  if (mapped === raw) return nativeFetch(input, init);
  const request = new Request(input instanceof Request ? input : new URL(raw, base), init);
  const options = {method:request.method, headers:request.headers, signal:request.signal,
    credentials:'omit', mode:'cors', redirect:request.redirect, cache:'no-store', referrerPolicy:'no-referrer'};
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return request.arrayBuffer().then(body => {
      if (body.byteLength > 2 * 1024 * 1024) throw new TypeError('Provider request exceeds 2 MiB');
      options.body = body;
      return nativeFetch(mapped, options);
    });
  }
  return nativeFetch(mapped, options);
};
const nativeOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, ...rest) {
  return nativeOpen.call(this, method, route(String(url)), ...rest);
};
for (const [name, properties] of [
  ['HTMLScriptElement',['src']], ['HTMLIFrameElement',['src']], ['HTMLImageElement',['src']],
  ['HTMLLinkElement',['href']], ['HTMLSourceElement',['src']], ['HTMLVideoElement',['src','poster']],
  ['HTMLAudioElement',['src']], ['HTMLFormElement',['action']]
]) {
  const type = window[name]; if (!type) continue;
  for (const property of properties) {
    const descriptor = Object.getOwnPropertyDescriptor(type.prototype,property);
    if (!descriptor || !descriptor.set || !descriptor.get) continue;
    Object.defineProperty(type.prototype,property,{...descriptor,
      get(){return original(descriptor.get.call(this));},
      set(value){descriptor.set.call(this,route(String(value)));}});
  }
}
const nativeAttribute = Element.prototype.setAttribute;
Element.prototype.setAttribute = function(name,value) {
  if (['src','href','action','formaction','poster','data'].includes(String(name).toLowerCase())) value=route(String(value));
  return nativeAttribute.call(this,name,value);
};
// Provider SDKs write their normal response fields. Surface those fields to the
// authorised parent, which validates the source window and names. Human submission
// remains an explicit operator action; this does not solve or submit a challenge.
let lastFields = '';
function publishFields() {
  const fields = {};
  for (const element of document.querySelectorAll('input[name],textarea[name]')) {
    if ((cfg.fields || []).includes(element.name) && element.value && element.value.length <= 65536) fields[element.name]=element.value;
  }
  const serialized=JSON.stringify(fields);
  if(serialized!==lastFields){lastFields=serialized;window.parent.postMessage({type:'blinder-fields',session:cfg.session,fields},'*');}
}
document.addEventListener('input',publishFields);
document.addEventListener('change',publishFields);
const timer=setInterval(publishFields,250);
window.addEventListener('pagehide',()=>clearInterval(timer),{once:true});
