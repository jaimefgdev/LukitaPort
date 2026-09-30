// authflow.js
// Pure sign-in decision logic (no DOM, no fetch), unit-tested with node:test.
// auth.js supplies the side effects.

/** Token from a location.hash such as "#token=abc" (or null). */
export function tokenFromHash(hash) {
    const params = new URLSearchParams(String(hash || '').replace(/^#/, ''));
    const token  = params.get('token');
    return token && token.trim() ? token.trim() : null;
}

/**
 * authenticate — make sure the browser holds a session for the right token.
 *
 * Rules:
 *   • A token in the URL fragment ALWAYS wins over any existing session:
 *     it is sent to the server even if a (possibly older) session cookie is
 *     still valid.
 *   • If that fragment token is rejected, the previous session is dropped
 *     (logout) and the sign-in dialog opens with an explanation — the app
 *     must never keep working silently with a different token.
 *   • Without a fragment token, an existing valid session is kept.
 *
 * deps: { hash, clearHash(), login(token) → bool, logout(), isAuthenticated()
 *         → bool, prompt(reason) → Promise }
 * Returns 'fragment' | 'session' | 'prompt'.
 */
export async function authenticate(deps) {
    const token = tokenFromHash(deps.hash);
    if (token) {
        deps.clearHash();                     // never leave the token in the address bar
        let ok = false;
        try { ok = await deps.login(token); } catch { ok = false; }
        if (ok) return 'fragment';
        try { await deps.logout(); } catch { /* best effort */ }
        await deps.prompt('invalid_fragment');
        return 'prompt';
    }
    let authed = false;
    try { authed = await deps.isAuthenticated(); } catch { authed = false; }
    if (authed) return 'session';
    await deps.prompt(null);
    return 'prompt';
}
