// Provider-only URL routing. No operator authority, completion bridge, or
// credentials are carried by this helper. Native browser policy checks still
// decide whether each mapped request is allowed.
const base = new URL(cfg.base);
const aliases = new Map(Object.entries(cfg.aliases));
const originals = new Map([...aliases].map(([upstream, local]) => [local, upstream]));
function route(value) {
  if (typeof value !== 'string' || !value || value[0] === '#') return value;
  let target;
  try { target = new URL(value, document.baseURI || base); } catch { return value; }
  if (originals.has(target.origin)) return value;
  const mapped = aliases.get(target.origin);
  if (!mapped || target.username || target.password) return value;
  const local = new URL(mapped);
  target.protocol = local.protocol;
  target.host = local.host;
  target.port = local.port;
  return target.href;
}
if (typeof window.fetch === 'function') {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function(input, init) {
    const raw = input instanceof Request ? input.url : String(input);
    const mapped = route(raw);
    if (mapped === raw) return nativeFetch(input, init);
    // Request is also a RequestInit dictionary: its native method, headers,
    // body stream, credentials, integrity, mode and signal carry through.
    const request = new Request(input instanceof Request ? input : new URL(raw, document.baseURI || base), init);
    return nativeFetch(new Request(mapped, request));
  };
}
const nativeOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, ...rest) {
  return nativeOpen.call(this, method, route(String(url)), ...rest);
};
for (const [name, properties] of [
  ['HTMLScriptElement', ['src']], ['HTMLIFrameElement', ['src']],
  ['HTMLImageElement', ['src']], ['HTMLLinkElement', ['href']],
  ['HTMLSourceElement', ['src']], ['HTMLVideoElement', ['src', 'poster']],
  ['HTMLAudioElement', ['src']], ['HTMLFormElement', ['action']],
  ['HTMLInputElement', ['formAction']], ['HTMLButtonElement', ['formAction']],
  ['HTMLObjectElement', ['data']]
]) {
  const type = window[name];
  if (!type) continue;
  for (const property of properties) {
    const descriptor = Object.getOwnPropertyDescriptor(type.prototype, property);
    if (!descriptor || !descriptor.set) continue;
    Object.defineProperty(type.prototype, property, {...descriptor,
      set(value) { descriptor.set.call(this, route(String(value))); }});
  }
}
const nativeAttribute = Element.prototype.setAttribute;
Element.prototype.setAttribute = function(name, value) {
  if (['src', 'href', 'action', 'formaction', 'poster', 'data'].includes(String(name).toLowerCase())) value = route(String(value));
  return nativeAttribute.call(this, name, value);
};
