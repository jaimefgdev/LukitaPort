// auth.js
// Obtains an API session before the rest of the app talks to /api/.
//
// The server issues an HttpOnly, SameSite=Strict cookie on POST /api/auth, so
// every later fetch() and EventSource is authenticated automatically and no
// other website can use it.  The token itself is never stored by the page.
//
// Login sources (decision logic in authflow.js):
//   1. #token=… in the URL fragment (the login URL printed by the server).
//      It always replaces the current session — also when the fragment
//      changes in an already open tab (hashchange), e.g. after a server
//      restart printed a new URL.  The fragment is removed immediately.
//   2. The sign-in dialog (#auth-overlay), also re-opened on any 401.

import { $, showToast } from './ui.js';
import { state } from './state.js';
import { authenticate } from './authflow.js';
import { setUnauthorizedHandler } from './http.js';

async function login(token) {
    const resp = await fetch('/api/auth', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ token }),
    });
    return resp.status === 204;
}

async function logout() {
    await fetch('/api/auth/logout', { method: 'POST' });
}

async function isAuthenticated() {
    const resp = await fetch('/api/auth/status');
    return resp.ok && (await resp.json()).authenticated === true;
}

function clearHash() {
    history.replaceState(null, '', location.pathname + location.search);
}

const REASONS = {
    invalid_fragment: {
        es: 'El token de la URL no es válido (¿el servidor se reinició con otro token?). Introduce el token actual.',
        en: 'The token in the URL is not valid (did the server restart with a new token?). Enter the current token.',
    },
    expired: {
        es: 'Tu sesión ya no es válida. Introduce el token de acceso.',
        en: 'Your session is no longer valid. Enter the access token.',
    },
};

let _prompting = null;      // single pending dialog shared by all callers

function promptForToken(reason) {
    const overlay = $('auth-overlay');
    const form    = $('auth-form');
    const input   = $('auth-token');
    const errorEl = $('auth-error');
    errorEl.textContent = reason && REASONS[reason] ? REASONS[reason][state.lang] : '';
    overlay.classList.remove('hidden');
    input.focus();

    if (_prompting) return _prompting;
    _prompting = new Promise(resolve => {
        form.addEventListener('submit', async function onSubmit(e) {
            e.preventDefault();
            errorEl.textContent = '';
            let ok = false;
            try { ok = await login(input.value.trim()); } catch { ok = false; }
            if (ok) {
                input.value = '';
                overlay.classList.add('hidden');
                form.removeEventListener('submit', onSubmit);
                _prompting = null;
                resolve();
            } else {
                errorEl.textContent = state.lang === 'es' ? 'Token no válido' : 'Invalid token';
                input.select();
            }
        });
    });
    return _prompting;
}

function hideOverlay() {
    $('auth-overlay').classList.add('hidden');
}

async function run() {
    const how = await authenticate({
        hash: location.hash,
        clearHash, login, logout, isAuthenticated,
        prompt: promptForToken,
    });
    if (how === 'fragment') hideOverlay();
    return how;
}

/** Resolve once the browser holds a valid session cookie. */
export async function ensureAuthenticated() {
    // A new login URL opened in this tab only changes the fragment (no reload).
    window.addEventListener('hashchange', async () => {
        if (!location.hash.includes('token=')) return;
        const how = await run();
        if (how === 'fragment') {
            showToast(state.lang === 'es'
                ? 'Sesión iniciada con el token de la URL.'
                : 'Signed in with the token from the URL.', 'ok');
        }
    });
    // Any 401 from the API re-opens the dialog.
    setUnauthorizedHandler(() => { promptForToken('expired'); });
    await run();
}
