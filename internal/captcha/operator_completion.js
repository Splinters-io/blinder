// This controller runs only in the trusted operator wrapper. The challenge
// remains at its dedicated origin and can supply only its configured fields.
const frame = document.querySelector('iframe');
const form = document.querySelector('form.fields');
if (!frame || !form) return;
const status = document.createElement('p');
status.setAttribute('role', 'status');
status.setAttribute('aria-live', 'polite');
form.insertAdjacentElement('afterend', status);
let submitting = false;
let automaticEnabled = c.automatic;

function setPending() {
  submitting = true;
  status.textContent = 'Submitting solution…';
  form.setAttribute('aria-busy', 'true');
  for (const button of form.querySelectorAll('button[type="submit"],input[type="submit"]')) button.disabled = true;
}
function enableRetry(message) {
  submitting = false;
  automaticEnabled = false;
  status.textContent = message;
  form.removeAttribute('aria-busy');
  for (const button of form.querySelectorAll('button[type="submit"],input[type="submit"]')) button.disabled = false;
}
function submitNative() {
  if (submitting) return;
  automaticEnabled = false;
  setPending();
  try {
    HTMLFormElement.prototype.submit.call(form);
  } catch {
    enableRetry('Submission could not start. Review the solution and submit again.');
  }
}
form.addEventListener('submit', event => {
  // Own the navigation before disabling the submitter. Relying on the event's
  // default submission after changing that button can leave browsers idle.
  event.preventDefault();
  submitNative();
});
window.addEventListener('message', event => {
  if (submitting || !c.origin || event.origin !== c.origin || event.source !== frame.contentWindow || !event.data ||
      event.data.type !== 'blinder-fields' || event.data.session !== c.session) return;
  let hasValue = false;
  for (const name of c.fields) {
    const value = event.data.fields && event.data.fields[name];
    if (typeof value !== 'string' || value.length > 65536) continue;
    for (const input of form.elements) if (input.name === name) input.value = value;
    if (value) hasValue = true;
  }
  if (!automaticEnabled || !hasValue) return;
  submitNative();
});
window.addEventListener('pageshow', event => {
  if (!event.persisted) return;
  enableRetry('Review the solution and submit again when ready.');
});
