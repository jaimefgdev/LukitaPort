// ui.js
// Handles: DOM helpers, toast, legal popup, language, table rendering, audit rendering.
//
// CSP changes vs previous version
// ─────────────────────────────────
// • window.copyText removed — copyText is an exported function; main.js wires
//   it into the event delegation system.
// • window._lastSSLData / window._lastCVEData removed — replaced by module-level
//   private variables _lastSSLData / _lastCVEData with explicit getters.
//   This eliminates implicit global state and makes re-renders on lang change
//   fully self-contained within the module.
// • initDelegationStyles() — injects ONE <style> block into <head> for the
//   .btn-cve-launch :hover rule that previously lived as onmouseover/onmouseout.
//   This is the only style injection; it runs once at app start.
//
// Batch rendering (rAF DocumentFragment) and smart auto-scroll are unchanged.

import { state, getRisk, RISK_LABELS } from './state.js';
import {
    escapeHTML,
    tmplHeadersAudit, tmplTechAudit, tmplPathsAudit,
    tmplSSLAudit, tmplCVEAudit, tmplCVEPlaceholder,
} from './templates.js';

// ── DOM helper ────────────────────────────────────────────────────────────────
export const $ = id => document.getElementById(id);

// Re-export so api.js / export.js can import escapeHTML from here
export { escapeHTML };

// ── Toast ─────────────────────────────────────────────────────────────────────
let _toastTimer = null;
export function showToast(msg, type = 'info', duration = 3500) {
    const t = $('toast');
    t.textContent = msg;
    t.className   = 'show ' + (type === 'error' ? 'toast-error' : type === 'ok' ? 'toast-ok' : '');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => { t.className = ''; }, duration);
}

// ── Legal popup ───────────────────────────────────────────────────────────────
export function initLegal() {
    const overlay = $('legal-overlay');
    if (localStorage.getItem('lukita_legal_ok') === '1') overlay.classList.add('hidden');
    $('btn-accept').addEventListener('click', () => {
        overlay.classList.add('hidden');
        localStorage.setItem('lukita_legal_ok', '1');
    });
}

// ── CSP delegation styles ─────────────────────────────────────────────────────
/**
 * initDelegationStyles — inject a single <style> element for dynamic component
 * hover states that previously required onmouseover/onmouseout JS attributes.
 *
 * Called once from main.js init.  Adding CSS rules this way is fully
 * compliant with `style-src 'self'` because <style> blocks in the
 * document are not restricted by script-src.
 *
 * Idempotent: checks for existing id before inserting.
 */
export function initDelegationStyles() {
    if (document.getElementById('lukita-delegation-styles')) return;
    const style = document.createElement('style');
    style.id = 'lukita-delegation-styles';
    style.textContent = `
        /* Hover for dynamically-rendered CVE launch button (replaces onmouseover/onmouseout) */
        .btn-cve-launch:hover {
            border-color: #ff0033 !important;
            color: #ff0033 !important;
        }
        /* Hover for discover host cards (replaces JS pointer feedback) */
        .discover-host-card:hover {
            border-color: rgba(0, 255, 136, .5) !important;
        }
    `;
    document.head.appendChild(style);
}

// ── Language ──────────────────────────────────────────────────────────────────
export function applyLang(lang) {
    state.lang = lang;
    document.body.className = lang;
    $('lang-label').textContent = lang === 'es' ? 'ES' : 'EN';
    Array.from($('scan-mode').options).forEach(o => { o.textContent = o.dataset[lang]; });
    if (state.results.length) renderTable();
    renderHistory();
    if (state.auditData) renderAudit(state.auditData);
    // Use module-level private cache (no window.* required)
    if (_lastCVEData) renderCVEAudit(_lastCVEData.results, _lastCVEData.versions);
    if (_lastSSLData) renderSSLAudit(_lastSSLData);
}

// ── Summary ───────────────────────────────────────────────────────────────────
export function updateSummary() {
    $('sum-open').textContent     = state.counts.open;
    $('sum-closed').textContent   = state.counts.closed;
    $('sum-filtered').textContent = state.counts.filtered;
    $('sum-total').textContent    = state.results.length;
}

// ── GeoIP badge ───────────────────────────────────────────────────────────────
export function renderGeo(geo) {
    if (!geo || !Object.keys(geo).length) return;
    const el = $('geo-badge');
    if (!el) return;
    const parts = [
        geo.flag   || '',
        geo.city   ? geo.city + ',' : '',
        geo.country  || '',
        geo.asn    ? '· ' + geo.asn  : '',
        geo.isp    ? '· ' + geo.isp  : '',
    ].filter(Boolean).join(' ');
    el.textContent   = parts;   // textContent is XSS-safe
    el.style.display = 'inline-flex';
}

// ── Scan dot blink ────────────────────────────────────────────────────────────
export function setDotBlink(on) {
    on
        ? $('results-dot').classList.add('dot-blink')
        : $('results-dot').classList.remove('dot-blink');
}

// ── Table helpers ─────────────────────────────────────────────────────────────
function translateState(s) {
    return ({
        en: { open: 'Open', closed: 'Closed', filtered: 'Filtered' },
        es: { open: 'Abierto', closed: 'Cerrado', filtered: 'Filtrado' },
    })[state.lang][s] || s;
}

function getRespClass(ms) {
    if (ms === null || ms === undefined) return '';
    if (ms < 100) return 'fast';
    if (ms < 500) return 'medium';
    return 'slow';
}

function cleanBanner(s) {
    if (!s) return '';
    return s.replace(/[^\x20-\x7E]/g, '').replace(/\s+/g, ' ').trim().substring(0, 60);
}

// ── Batch rendering engine (rAF + DocumentFragment) ──────────────────────────

let _rowQueue = [];
let _rafId    = null;

function _scheduleFlush() {
    if (_rafId !== null) return;
    _rafId = requestAnimationFrame(_flushBatch);
}

function _cancelFlush() {
    if (_rafId !== null) {
        cancelAnimationFrame(_rafId);
        _rafId = null;
    }
}

function _buildRow(d) {
    const tr   = document.createElement('tr');
    tr.dataset.state = d.state;
    tr.dataset.port  = d.port;

    const risk = getRisk(d.port);
    const rl   = RISK_LABELS[state.lang][risk];

    const riskCell = d.state === 'open'
        ? `<span class="risk risk-${risk}">${rl}</span>`
        : '<span style="color:#2a2a2a;font-family:var(--font-mono);font-size:10px">—</span>';

    const ver      = state.versions[d.port];
    const verRaw   = ver ? cleanBanner(ver.version) : '';
    const verSafe  = escapeHTML(verRaw);
    const verHtml  = verSafe
        ? `<span class="version-tag loaded" title="${verSafe}">${verSafe.length > 36 ? verSafe.substring(0, 35) + '…' : verSafe}</span>`
        : '<span class="version-tag">—</span>';

    const serviceHtml = escapeHTML(d.service || '');
    const stateHtml   = escapeHTML(translateState(d.state));
    const respMs      = d.response_time_ms;
    const respHtml    = respMs !== null && respMs !== undefined ? `${respMs} ms` : '—';

    tr.innerHTML = `<td class="col-port">${d.port}</td><td><span class="badge badge-${d.state}">${stateHtml}</span></td><td class="col-service">${serviceHtml}</td><td>${riskCell}</td><td class="col-time resp-time ${getRespClass(respMs)}">${respHtml}</td><td>${verHtml}</td>`;
    return tr;
}

/**
 * _flushBatch — rAF callback.
 * 1. Measures smart-scroll intent (read phase, no layout mutation).
 * 2. Builds all queued rows into a DocumentFragment (zero intermediate reflows).
 * 3. Single appendChild (one reflow).
 * 4. Conditionally scrolls (only if user was near the bottom).
 */
function _flushBatch() {
    _rafId = null;
    const rows = _rowQueue.splice(0);
    if (!rows.length) return;

    const tbody = $('results-body');
    if (!tbody) return;
    const wrap = tbody.closest('.table-wrap');

    // Smart-scroll: measure BEFORE DOM mutation
    const wasNearBottom = !wrap
        ? false
        : wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 80;

    const frag = document.createDocumentFragment();
    rows.forEach(d => frag.appendChild(_buildRow(d)));
    tbody.appendChild(frag);

    if (wasNearBottom && wrap) wrap.scrollTop = wrap.scrollHeight;
}

/** flushAndDrain — synchronously flush remaining queue (called by stopScan). */
export function flushAndDrain() {
    _cancelFlush();
    _flushBatch();
}

/** appendRow — O(1) push to queue; schedules a single rAF flush. */
export function appendRow(d) {
    _rowQueue.push(d);
    _scheduleFlush();
}

/** renderTable — full synchronous re-render (filter/language change). */
export function renderTable() {
    _cancelFlush();
    _rowQueue = [];

    const tbody = $('results-body');
    tbody.innerHTML = '';

    const f = state.filter === 'all'
        ? state.results
        : state.results.filter(r => r.state === state.filter);

    if (!f.length) {
        const msg = state.lang === 'es' ? 'Sin resultados para este filtro' : 'No results for this filter';
        tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">[ _ ]<br>${msg}</div></td></tr>`;
        return;
    }

    const wrap = tbody.closest('.table-wrap');
    const frag = document.createDocumentFragment();
    f.forEach(d => frag.appendChild(_buildRow(d)));
    tbody.appendChild(frag);
    if (wrap) wrap.scrollTop = wrap.scrollHeight;
}

export function showError(msg) {
    _cancelFlush();
    _rowQueue = [];
    $('results-body').innerHTML = `<tr><td colspan="6"><div class="empty-state" style="color:#ff0033">✕<br>${escapeHTML(msg)}</div></td></tr>`;
}

// ── History ───────────────────────────────────────────────────────────────────
const HIST_KEY = 'lukita_history';

export const loadHistory  = () => { try { return JSON.parse(localStorage.getItem(HIST_KEY)) || []; } catch { return []; } };

export function saveHistory(entry) {
    let h = loadHistory();
    if (h.length && h[0].target === entry.target) { h[0] = entry; } else { h.unshift(entry); if (h.length > 5) h = h.slice(0, 5); }
    localStorage.setItem(HIST_KEY, JSON.stringify(h));
}

export function renderHistory() {
    const h     = loadHistory();
    const panel = $('history-panel');
    const list  = $('history-list');
    if (!h.length) { panel.style.display = 'none'; return; }
    panel.style.display = 'block';

    list.innerHTML = h.map((item, idx) => {
        const openPorts     = item.openPorts || [];
        const riskHighCount = item.riskHigh  || 0;
        const riskMedCount  = item.riskMed   || 0;

        const chipOpen = `<span class="hc-chip hc-chip-open">● ${item.open} open</span>`;
        const chipHigh = riskHighCount ? `<span class="hc-chip hc-chip-high">▲ ${riskHighCount} ${state.lang === 'es' ? 'alto' : 'high'}</span>` : '';
        const chipMed  = riskMedCount  ? `<span class="hc-chip hc-chip-med">◆ ${riskMedCount} ${state.lang === 'es' ? 'medio' : 'med'}</span>`   : '';

        const modeLabel = state.lang === 'es'
            ? { quick: 'rápido', custom: 'personalizado', full: 'completo' }[item.mode] || item.mode || '—'
            : { quick: 'quick',  custom: 'custom',        full: 'full'    }[item.mode] || item.mode || '—';

        const MAX_PORTS   = 8;
        const shown       = openPorts.slice(0, MAX_PORTS);
        const hidden      = openPorts.length - shown.length;
        const portTagsHtml = shown.length
            ? shown.map(p => `<span class="hc-port-tag">${p.port}<span class="svc">${escapeHTML(p.service)}</span></span>`).join('')
              + (hidden > 0 ? `<span class="hc-port-more">+${hidden} más</span>` : '')
            : `<span style="color:#2a2a2a;font-family:var(--font-mono);font-size:10px">${state.lang === 'es' ? 'Sin puertos abiertos' : 'No open ports'}</span>`;

        const ipBadge = item.ip ? `<span class="hc-ip">${escapeHTML(item.ip)}</span>` : '';

        return `<div class="history-item">
            <div class="history-card">
                <div class="hc-main">
                    <div class="hc-top">
                        <span class="hc-target">${escapeHTML(item.target)}</span>
                        ${ipBadge}
                        <span class="hc-date">${escapeHTML(item.date)}</span>
                    </div>
                    <div class="hc-chips">
                        ${chipOpen}${chipHigh}${chipMed}
                        <span class="hc-chip">${escapeHTML(modeLabel)}</span>
                        <span class="hc-chip">${escapeHTML(item.profile || 'normal')}</span>
                        <span class="hc-chip" style="color:#333">${item.total || '?'} ${state.lang === 'es' ? 'esc.' : 'scanned'}</span>
                    </div>
                    <div class="hc-ports">${portTagsHtml}</div>
                </div>
                <div class="hc-actions">
                    <button class="btn-reload" data-idx="${idx}">↺ ${state.lang === 'es' ? 'Relanzar' : 'Retry'}</button>
                </div>
            </div>
        </div>`;
    }).join('');

    return list;
}

// ── Audit render cache (module-private, replaces window._lastSSLData etc.) ────

let _lastSSLData = null;
let _lastCVEData = null;

/** getLastSSLData / getLastCVEData — used by applyLang for re-renders. */
export const getLastSSLData = () => _lastSSLData;
export const getLastCVEData = () => _lastCVEData;

// ── Audit rendering ───────────────────────────────────────────────────────────

export function renderAudit(data) {
    if (!data) return;
    $('pane-headers').innerHTML      = tmplHeadersAudit(data.headers, state.lang);
    $('pane-technologies').innerHTML = tmplTechAudit(data.technologies, state.lang);
    $('pane-paths').innerHTML        = tmplPathsAudit(data.paths, state.lang);

    const tabs = document.querySelectorAll('.audit-tab');
    if (data.headers) {
        const miss = data.headers.missing?.length || 0;
        const t    = tabs[0];
        if (t) t.innerHTML = `🔒 <span class="es">Cabeceras HTTP</span><span class="en">HTTP Headers</span>${miss ? ` <span class="tab-badge-red">${miss}</span>` : ''}`;
    }
    if (data.technologies) {
        const cnt = data.technologies.count || 0;
        const t   = tabs[1];
        if (t) t.innerHTML = `🔬 <span class="es">Tecnologías</span><span class="en">Technologies</span>${cnt ? ` <span class="tab-badge-blue">${cnt}</span>` : ''}`;
    }
    if (data.paths) {
        const cnt  = data.paths.total_found || 0;
        const high = data.paths.found?.filter(f => f.severity === 'high').length || 0;
        const t    = tabs[2];
        if (t) t.innerHTML = `🗂 <span class="es">Rutas Sensibles</span><span class="en">Sensitive Paths</span>${cnt ? ` <span class="${high ? 'tab-badge-red' : 'tab-badge-yellow'}">${cnt}</span>` : ''}`;
    }
}

export function renderSSLAudit(data) {
    _lastSSLData            = data;   // module-private cache (replaces window._lastSSLData)
    $('pane-ssl').innerHTML = tmplSSLAudit(data, state.lang);
}

export function renderCVEAudit(results, versionsPayload) {
    _lastCVEData = { results, versions: versionsPayload };   // replaces window._lastCVEData

    const pane = $('pane-cve');
    const out  = tmplCVEAudit(results, versionsPayload, state.lang);

    if (typeof out === 'string') {
        pane.innerHTML = out;
        return;
    }

    pane.innerHTML = out.html;
    document.querySelectorAll('.audit-tab').forEach(t => {
        if (t.dataset.pane === 'cve') {
            t.innerHTML = `🐛 CVE${out.totalCVEs ? ` <span class="tab-badge-red">${out.totalCVEs}</span>` : ''}`;
        }
    });
}

export function renderCVEPlaceholder() {
    $('pane-cve').innerHTML = tmplCVEPlaceholder(state.lang);
}

// ── copyText ──────────────────────────────────────────────────────────────────
/**
 * copyText — copy text to clipboard and give visual feedback on the button.
 *
 * No longer attached to window.  Called exclusively by the event delegation
 * handler in main.js when it sees data-action="copy".
 */
export function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = '✓';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
    }).catch(() => {});
}
