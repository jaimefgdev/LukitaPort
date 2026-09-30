// auth.js
// Obtains an API session before the rest of the app talks to /api/.
//
// The server issues an HttpOnly, SameSite=Strict cookie on POST /api/auth, so
// every later fetch() and EventSource is authenticated automatically and no
// other website can use it.  The token itself is never stored by the page.
//
// Login sources, in order:
//   1. #token=… in the URL fragment (the login URL printed by the server).
//      The fragment is never sent to the server and is removed from the
//      address bar immediately.
//   2. The sign-in dialog (#auth-overlay).

import { $ } from './ui.js';
import { state } from './state.js';

async function login(token) {
    const resp = await fetch('/api/auth', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ token }),
    });
    return resp.status === 204;
}

async function isAuthenticated() {
    try {
        const resp = await fetch('/api/auth/status');
        return resp.ok && (await resp.json()).authenticated === true;
    } catch {
        return false;
    }
}

function tokenFromFragment() {
    const params = new URLSearchParams(location.hash.slice(1));
    const token  = params.get('token');
    if (token) history.replaceState(null, '', location.pathname + location.search);
    return token;
}

function promptForToken() {
    const overlay = $('auth-overlay');
    const form    = $('auth-form');
    const input   = $('auth-token');
    const errorEl = $('auth-error');
    overlay.classList.remove('hidden');
    input.focus();

    return new Promise(resolve => {
        form.addEventListener('submit', async function onSubmit(e) {
            e.preventDefault();
            errorEl.textContent = '';
            let ok = false;
            try { ok = await login(input.value.trim()); } catch { ok = false; }
            if (ok) {
                input.value = '';
                overlay.classList.add('hidden');
                form.removeEventListener('submit', onSubmit);
                resolve();
            } else {
                errorEl.textContent = state.lang === 'es' ? 'Token no válido' : 'Invalid token';
                input.select();
            }
        });
    });
}

/** Resolve once the browser holds a valid session cookie. */
export async function ensureAuthenticated() {
    const fragmentToken = tokenFromFragment();
    if (fragmentToken && await login(fragmentToken).catch(() => false)) return;
    if (await isAuthenticated()) return;
    await promptForToken();
}
