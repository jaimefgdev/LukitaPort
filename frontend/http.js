// http.js
// apiFetch — fetch() wrapper used for every /api/ call.  Non-2xx responses
// (and network failures) become ApiRequestError with a clear, localised
// message (errors.js), and a 401 asks auth.js to show the sign-in dialog.

import { state } from './state.js';
import { describeError, errorInfoFromBody } from './errors.js';

export class ApiRequestError extends Error {
    constructor(info, message) {
        super(message);
        this.name   = 'ApiRequestError';
        this.status = info.status;
        this.code   = info.code;
        this.detail = info.detail;
    }
}

let _onUnauthorized = null;

/** auth.js registers the handler that re-opens the sign-in dialog. */
export function setUnauthorizedHandler(fn) { _onUnauthorized = fn; }

export function notifyUnauthorized() {
    if (_onUnauthorized) _onUnauthorized();
}

export function errorMessage(info) {
    return describeError(info, state.lang);
}

export async function apiFetch(url, options = {}) {
    let resp;
    try {
        resp = await fetch(url, options);
    } catch (e) {
        if (e.name === 'AbortError') throw e;
        const info = { status: 0, code: 'network', detail: '' };
        throw new ApiRequestError(info, errorMessage(info));
    }
    if (resp.ok) return resp;

    let body = null;
    try { body = await resp.json(); } catch { /* not JSON */ }
    const info = errorInfoFromBody(resp.status, body);
    if (resp.status === 401) notifyUnauthorized();
    throw new ApiRequestError(info, errorMessage(info));
}

/** apiJSON — apiFetch + parse JSON. */
export async function apiJSON(url, options = {}) {
    return (await apiFetch(url, options)).json();
}
