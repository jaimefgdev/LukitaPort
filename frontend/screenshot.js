// screenshot.js
// Polls the backend for a web screenshot after /api/screenshot/capture and
// shows it in the audit panel.  The capture runs in the background on the
// server, so poll with a short interval instead of guessing a fixed delay.

import { $ } from './ui.js';
import { apiFetch } from './http.js';

const POLL_INTERVAL_MS = 2_000;
const POLL_TIMEOUT_MS  = 40_000;

let _currentUrl = null;     // object URL of the image shown now (revoked on replace)
let _pollToken  = 0;        // a newer scan cancels older polls

/**
 * pollScreenshot — wait for the screenshot of ``target`` and render it.
 * Resolves true when shown, false on timeout / superseded / error.
 */
export async function pollScreenshot(target) {
    const token    = ++_pollToken;
    const deadline = Date.now() + POLL_TIMEOUT_MS;

    while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
        if (token !== _pollToken) return false;
        let resp;
        try {
            // apiFetch: a 401 re-opens the sign-in dialog.
            resp = await apiFetch(`/api/screenshot?target=${encodeURIComponent(target)}`);
        } catch {
            return false;
        }
        if (resp.status === 204) continue;           // not ready yet
        renderScreenshot(await resp.blob());
        return true;
    }
    return false;
}

export function resetScreenshot() {
    _pollToken++;
    const tab = document.querySelector('.audit-tab[data-pane="screenshot"]');
    if (tab) tab.style.display = 'none';
}

function renderScreenshot(blob) {
    const pane = $('pane-screenshot');
    if (!pane) return;
    if (_currentUrl) URL.revokeObjectURL(_currentUrl);
    _currentUrl = URL.createObjectURL(blob);

    // img.src is a blob: URL built from the server response — no markup injection.
    const img         = document.createElement('img');
    img.src           = _currentUrl;
    img.alt           = 'Screenshot';
    img.style.cssText = 'width:100%;border-radius:4px;border:1px solid #1e1e1e';

    const wrapper         = document.createElement('div');
    wrapper.style.padding = '20px';
    wrapper.appendChild(img);

    pane.replaceChildren(wrapper);

    const tab = document.querySelector('.audit-tab[data-pane="screenshot"]');
    if (tab) tab.style.display = 'inline-flex';
}
