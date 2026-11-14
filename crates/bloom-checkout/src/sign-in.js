(() => {
  // Password and code fields mark a sign-in in progress. A new-password field,
  // or a password with its confirmation, marks a new account.
  const inputs = [...document.querySelectorAll('input')]
    .filter(e => e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden');
  const passwords = inputs.filter(e => e.type === 'password');
  const words = e => [e.name, e.id, e.placeholder, e.getAttribute('aria-label'), e.labels?.[0]?.innerText].join(' ');
  const code = inputs.some(e => (e.getAttribute('autocomplete') || '').includes('one-time-code')
    || /\b(code|otp|verification|pin)\b/i.test(words(e)));
  return {
    secret: passwords.length > 0 || code,
    signup: passwords.length > 1 || passwords.some(e => (e.getAttribute('autocomplete') || '').includes('new-password')),
    ready: document.readyState === 'complete',
  };
})()
