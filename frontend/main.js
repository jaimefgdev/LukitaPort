// main.js
// Entry point. Imports all modules and wires up event listeners.
//
// CSP compliance changes vs previous version
// ──────────────────────────────────────────
// • window.launchCVELookup removed — CVE launch now handled by event delegation.
// • window._pollScreenshot removed — converted to module-local async function
//   pollScreenshot() exported for api.js to call directly after screenshot POST.
// • All inline onclick / onmouseover / onmouseout attributes have been removed
//   from templates.js / ui.js.  A single delegate on document.body intercepts
//   data-action clicks for: "copy", "launch-cve", "scan-host".
//
// Event delegation contract
// ─────────────────────────
// Any element anywhere in the document (including dynamically injected HTML)
// can trigger an action by setting data-action on itself or a parent.
// The delegate uses Element.closest() to find the nearest action element,
// so it works for both the element itself and nested children (e.g. <span>
// inside a <button data-action="copy">).
//
//   data-action="copy"
//       data-copy-text="{text}"        Copy text to clipboard.
//
//   data-action="launch-cve"           Run CVE batch lookup.
//
//   data-action="scan-host"
//       data-host="{ip|hostname}"      Load host into target input & focus.
//
// Adding a new action in the future: add the data-action attr in templates.js
// and add a case in the _ACTION_HANDLERS map below.  Zero changes to main.js
// boilerplate needed.

import { state, initConfig }                         from './state.js';
import { $, initLegal, initDelegationStyles, applyLang,
         renderHistory, setDotBlink, updateSummary,
         showError, renderTable, copyText }           from './ui.js';
import { startScan, stopScan, runFingerprint,
         launchAudit, launchDiscover, launchSubdomains,
         cleanTarget, launchCVELookup }               from './api.js';
import { exportJSON, exportCSV, exportHTMLReport,
         exportPDF, exportMarkdown }                  from './export.js';

// ── Init ───────────────────────────────────────────────────────────────────────
(async () => {
    await initConfig();         // Fetch PORT_RISK from backend before renders
    initLegal();
    initDelegationStyles();     // Inject CSS for dynamic component hover states
    renderHistory();
})();

// ── Global event delegation ───────────────────────────────────────────────────
/**
 * _ACTION_HANDLERS — map from data-action value to handler function.
 *
 * Each handler receives (element, event) where element is the closest
 * ancestor that has a [data-action] attribute.
 *
 * This is the single authoritative list of all delegated actions.
 * To add a new action: add an entry here + set data-action on the element.
 */
const _ACTION_HANDLERS = {

    /**
     * "copy" — copy data-copy-text to clipboard.
     * Delegates to copyText() from ui.js (not on window).
     */
    'copy': (el) => {
        const text = el.dataset.copyText;
        if (text !== undefined) copyText(text, el);
    },

    /**
     * "launch-cve" — trigger the CVE batch lookup.
     * Replaces: onclick="window.launchCVELookup && window.launchCVELookup()"
     */
    'launch-cve': () => {
        launchCVELookup();
    },

    /**
     * "scan-host" — load an IP or hostname into the target input and focus.
     * Replaces: onclick="document.getElementById('target').value='${ip}';..."
     * Used by discover host cards and subdomain scan buttons.
     */
    'scan-host': (el) => {
        const host = el.dataset.host;
        if (!host) return;
        const targetInput = $('target');
        targetInput.value = host;
        targetInput.style.borderColor = '';
        targetInput.dispatchEvent(new Event('input'));
        targetInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        targetInput.focus();
    },
};

/**
 * Single delegated click handler on document.body.
 *
 * Performance note: one listener on body is faster than N listeners on
 * dynamically-created elements and eliminates the need to remove/add listeners
 * when content is replaced via innerHTML.  The Element.closest() call is O(depth)
 * and negligible for typical DOM trees.
 */
document.body.addEventListener('click', e => {
    const el = e.target.closest('[data-action]');
    if (!el) return;

    const action  = el.dataset.action;
    const handler = _ACTION_HANDLERS[action];
    if (handler) {
        e.stopPropagation();
        handler(el, e);
    }
});

// ── Language toggle ────────────────────────────────────────────────────────────
$('lang-btn').addEventListener('click', () => {
    applyLang(state.lang === 'es' ? 'en' : 'es');
    $('lang-btn').classList.remove('pulse');
    void $('lang-btn').offsetWidth;
    $('lang-btn').classList.add('pulse');
    $('lang-btn').addEventListener('animationend', () => $('lang-btn').classList.remove('pulse'), { once: true });
});

// ── Target input cleanup ───────────────────────────────────────────────────────
$('target').addEventListener('input', function () {
    this.style.borderColor = /^https?:\/\//i.test(this.value) ? '#ffaa00' : '';
});
$('target').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !state.scanning) startScan();
});

// ── Scan mode — custom range toggle ───────────────────────────────────────────
$('scan-mode').addEventListener('change', () => {
    $('custom-range').classList.toggle('visible', $('scan-mode').value === 'custom');
});

// ── Timeout slider ─────────────────────────────────────────────────────────────
$('timeout').addEventListener('input', () => {
    $('timeout-val').textContent = parseFloat($('timeout').value).toFixed(1) + 's';
});

// ── Scan / Stop ────────────────────────────────────────────────────────────────
$('btn-scan').addEventListener('click', () => {
    state.scanning ? stopScan() : startScan();
});

// ── Filter tabs ────────────────────────────────────────────────────────────────
document.querySelectorAll('.filter-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        state.filter = tab.dataset.filter;
        renderTable();
    });
});

// ── Audit tabs ─────────────────────────────────────────────────────────────────
document.querySelectorAll('.audit-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.audit-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        document.querySelectorAll('.audit-pane').forEach(p => p.classList.remove('active'));
        $('pane-' + tab.dataset.pane).classList.add('active');
    });
});

// ── History reload ─────────────────────────────────────────────────────────────
$('history-list')?.addEventListener('click', async e => {
    const btn = e.target.closest('.btn-reload');
    if (!btn) return;
    const items = JSON.parse(localStorage.getItem('lukita_history') || '[]');
    const item  = items[parseInt(btn.dataset.idx)];
    if (!item) return;
    $('target').value = item.target;
    startScan();
});

// ── Anon mode toggle ───────────────────────────────────────────────────────────
document.getElementById('anon-mode')?.addEventListener('change', function () {
    const dot    = document.getElementById('anon-dot');
    const status = document.getElementById('anon-status');
    if (this.checked) {
        dot.style.background = '#00ff88';
        dot.style.boxShadow  = '0 0 8px #00ff88';
        const profileSel = document.getElementById('scan-profile');
        if (profileSel) profileSel.value = 'stealth';
        if (status) status.innerHTML = `<span class="es" style="color:#00cc66">✓ Activado — perfil Stealth forzado · delays aleatorios</span><span class="en" style="color:#00cc66">✓ Enabled — Stealth profile forced · random delays</span>`;
    } else {
        dot.style.background = '#333';
        dot.style.boxShadow  = 'none';
        if (status) status.innerHTML = `<span class="es">Desactivado — fuerza perfil Stealth + delays aleatorios</span><span class="en">Disabled — forces Stealth profile + random delays</span>`;
    }
});

document.querySelector('.anon-toggle')?.addEventListener('click', function (e) {
    if (e.target.tagName === 'BUTTON') return;
    const cb = document.getElementById('anon-mode');
    if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change')); }
});

$('btn-fingerprint').addEventListener('click', runFingerprint);

// ── Export buttons ─────────────────────────────────────────────────────────────
$('btn-json').addEventListener('click', exportJSON);
$('btn-csv').addEventListener('click',  exportCSV);
$('btn-html').addEventListener('click', exportHTMLReport);
$('btn-pdf').addEventListener('click',  exportPDF);
$('btn-md').addEventListener('click',   exportMarkdown);

// ── Network Discovery ──────────────────────────────────────────────────────────
$('btn-discover')?.addEventListener('click', launchDiscover);
$('discover-cidr')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') launchDiscover();
});

// ── Subdomain Enumeration ──────────────────────────────────────────────────────
$('btn-subdomains')?.addEventListener('click', launchSubdomains);
$('subdomain-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') launchSubdomains();
});

// ── Screenshot polling ────────────────────────────────────────────────────────
/**
 * pollScreenshot — wait for a backend screenshot and render it when ready.
 *
 * Previously lived on window._pollScreenshot (CSP violation).
 * Now a module-level async function exported so api.js can call it
 * directly after triggering the capture POST.
 *
 * @param {string} target  Hostname or IP passed to /api/screenshot
 */
export async function pollScreenshot(target) {
    await new Promise(r => setTimeout(r, 12_000));
    try {
        const resp = await fetch(`/api/screenshot?target=${encodeURIComponent(target)}`);
        if (resp.status === 200) {
            const blob    = await resp.blob();
            const imgUrl  = URL.createObjectURL(blob);
            const pane    = $('pane-screenshot');
            if (pane) {
                // img.src is a blob: URL — safe, no XSS risk
                const img         = document.createElement('img');
                img.src           = imgUrl;
                img.alt           = 'Screenshot';
                img.style.cssText = 'width:100%;border-radius:4px;border:1px solid #1e1e1e';

                const wrapper         = document.createElement('div');
                wrapper.style.padding = '20px';
                wrapper.appendChild(img);

                pane.innerHTML = '';
                pane.appendChild(wrapper);

                const screenshotTab = document.querySelector('.audit-tab[data-pane="screenshot"]');
                if (screenshotTab) screenshotTab.style.display = 'inline-flex';
            }
        }
    } catch { /* screenshot unavailable — silently ignore */ }
}
