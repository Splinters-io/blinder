// Completion uses native top-level form navigation. Cookie-only fetch/XHR is
// intentionally not authorized for operator controls. Only the server's receipt
// after a successful POST may tell the operator that a solution was submitted.
const status = document.createElement('p');
status.setAttribute('role', 'status');
status.setAttribute('aria-live', 'polite');
let submitting = false;

if (!c.automatic) {
  const frame = document.querySelector('iframe');
  const form = document.querySelector('form.fields');
  if (!form) return;
  form.insertAdjacentElement('afterend', status);
  form.addEventListener('submit', event => {
    if (submitting) { event.preventDefault(); return; }
    submitting = true;
    status.textContent = 'Submitting solution…';
    form.setAttribute('aria-busy', 'true');
    for (const button of form.querySelectorAll('button[type="submit"],input[type="submit"]')) button.disabled = true;
  });
  window.addEventListener('message', event => {
    if (submitting || !frame || event.source !== frame.contentWindow || !event.data ||
        event.data.type !== 'blinder-fields' || event.data.session !== c.session) return;
    for (const name of c.fields) {
      const value = event.data.fields && event.data.fields[name];
      if (typeof value !== 'string' || value.length > 65536) continue;
      for (const input of form.elements) if (input.name === name) input.value = value;
    }
  });
  window.addEventListener('pageshow', event => {
    if (!event.persisted) return;
    submitting = false;
    status.textContent = 'Review the solution and submit again when ready.';
    form.removeAttribute('aria-busy');
    for (const button of form.querySelectorAll('button[type="submit"],input[type="submit"]')) button.disabled = false;
  });
  return;
}

const retry = document.createElement('button');
retry.type = 'button';
retry.textContent = 'Retry submission';
retry.hidden = true;
document.body.append(status, retry);
let timer;
let automaticEnabled = true;
let pendingForm;
const observer = new MutationObserver(() => trySend());
function stopWatching() {
  clearInterval(timer);
  observer.disconnect();
}
function trySend(manual = false) {
  if (submitting || (!manual && !automaticEnabled)) return;
  const values = [];
  for (const name of c.fields) {
    for (const element of document.querySelectorAll('input[name],textarea[name]')) {
      if (element.name === name && element.value && element.value.length <= 65536) {
        values.push([name, element.value]);
        break;
      }
    }
  }
  if (!values.length) return;
  submitting = true;
  automaticEnabled = false;
  stopWatching();
  retry.hidden = true;
  status.textContent = 'Submitting solution…';
  const form = document.createElement('form');
  pendingForm = form;
  form.method = 'POST';
  form.action = '/__blinder/captcha/challenge/' + encodeURIComponent(c.session);
  form.hidden = true;
  for (const [name, value] of values) {
    const input = document.createElement('input');
    input.type = 'hidden'; input.name = name; input.value = value;
    form.append(input);
  }
  document.body.append(form);
  try {
    HTMLFormElement.prototype.submit.call(form);
  } catch {
    form.remove();
    pendingForm = null;
    submitting = false;
    status.textContent = 'Submission could not start. Please retry.';
    retry.hidden = false;
  }
}
retry.addEventListener('click', () => trySend(true));
window.addEventListener('pagehide', stopWatching, {once: true});
window.addEventListener('pageshow', event => {
  if (!event.persisted) return;
  if (pendingForm) { pendingForm.remove(); pendingForm = null; }
  submitting = false;
  status.textContent = 'Review the solution, then retry if it was not accepted.';
  retry.hidden = false;
});
observer.observe(document.body, {childList: true, subtree: true, attributes: true, characterData: true});
timer = setInterval(() => trySend(), 500);
trySend();
