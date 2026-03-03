// api.js
// Handles: EventSource streaming scan, fingerprint, audit, SSL, CVE, discover, subdomains.
//
// Memory-safety contract for EventSource:
// ────────────────────────────────────────
// Every EventSource is created through _createEventSource() and destroyed
// through _destroyEventSource().  The destroy function:
//   1. Nulls out onmessage / onerror / onopen  ← removes internal V8 references
//   2. Calls .close()                           ← closes TCP connection
//   3. Nulls state.eventSource                 ← releases the JS object reference
//
// Without step 1, the browser's event dispatch machinery can keep a reference
// to the EventSource alive even after .close(), preventing GC.  Over many
// successive scans this causes a memory leak.

import { state }     from './state.js';
import { $, showToast, appendRow, renderTable, updateSummary, setDotBlink,
         showError, saveHistory, renderHistory, renderAudit, renderSSLAudit,
         renderCVEAudit, renderCVEPlaceholder, renderGeo,
         flushAndDrain }  from './ui.js';
import { tmplDiscoverOutput, tmplSubdomainsOutput, tmplCVELoading } from './templates.js';

// ── Timeout constants (must match backend config) ─────────────────────────────
const NMAP_BASE_TIMEOUT_SEC   = 20;
const NMAP_PER_PORT_SEC       = 4;

// ── AbortController manager ──────────────────────────────────────────────────
// Categorized by action key.  Calling getController(key) aborts any previous
// in-flight request for the same action before creating a new one.
const _controllers = new Map();

function getController(key) {
    if (_controllers.has(key)) {
        try { _controllers.get(key).abort(); } catch (_) {}
    }
    const ctrl = new AbortController();
    _controllers.set(key, ctrl);
    return ctrl;
}

function clearController(key) {
    _controllers.delete(key);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
export function cleanTarget(raw) {
    let t = raw.trim().replace(/^https?:\/\//i, '').split('/')[0].split('?')[0].split('#')[0];
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(t.split(':')[0]);
    if (!isIP) t = t.split(':')[0];
    return t.trim();
}

function getTs()   { return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19); }
function getSlug() { return (state.scanMeta?.ip ?? 'scan').replace(/\./g, '_'); }

// ── EventSource lifecycle management ─────────────────────────────────────────

/**
 * _createEventSource — build a new EventSource and store it in state.
 *
 * Always call _destroyEventSource() on any existing source first
 * (startScan() does this automatically).
 *
 * @param {string} url  Full URL including query params.
 * @returns {EventSource}
 */
function _createEventSource(url) {
    const es = new EventSource(url);
    state.eventSource = es;
    return es;
}

/**
 * _destroyEventSource — hermetically close and dereference an EventSource.
 *
 * Three-step shutdown:
 *  1. Null all handler properties → the EventSource can no longer fire events
 *     and the browser's internal dispatch table releases its closure references.
 *  2. Close the underlying HTTP stream → frees TCP/network resources.
 *  3. Null state.eventSource → removes the last strong JS reference so the
 *     GC can collect the object.
 *
 * Idempotent: safe to call even when state.eventSource is already null.
 */
function _destroyEventSource() {
    const es = state.eventSource;
    if (!es) return;

    // Step 1 — null all registered handlers first
    // This is the critical step that prevents listener leaks.
    // If we called .close() before nulling these, the V8 heap might retain
    // the EventSource until the next GC cycle via the handler closures.
    es.onmessage = null;
    es.onerror   = null;
    es.onopen    = null;

    // Step 2 — close the connection
    try { es.close(); } catch (_) {}

    // Step 3 — release the JS reference
    state.eventSource = null;
}

// ── Scan (SSE) ────────────────────────────────────────────────────────────────
export function startScan() {
    const target = cleanTarget($('target').value);
    if (!target) { $('target').focus(); return; }
    $('target').value = target;
    $('target').style.borderColor = '';

    state.results   = [];
    state.counts    = { open: 0, closed: 0, filtered: 0 };
    state.scanMeta  = null;
    state.scanning  = true;
    state.versions  = {};
    state.auditData = null;
    state.geoData   = null;

    $('btn-scan').querySelector('.es').textContent = 'Detener';
    $('btn-scan').querySelector('.en').textContent = 'Stop';
    $('btn-scan').style.borderColor = '#ff4444';
    $('btn-scan').style.color       = '#ff4444';
    $('results-body').innerHTML     = '';
    $('status-bar').classList.add('visible');
    $('results-panel').classList.add('visible');
    $('summary-panel').style.display = 'none';
    $('audit-panel').classList.remove('visible');
    $('btn-fingerprint').style.display = 'none';
    $('fp-status-bar').textContent = '';
    const geoBadge = $('geo-badge');
    if (geoBadge) geoBadge.style.display = 'none';
    setDotBlink(true);
    updateSummary();

    const mode    = $('scan-mode').value;
    const profile = $('scan-profile').value;
    const anonEl  = document.getElementById('anon-mode');
    const isAnon  = anonEl?.checked || false;

    const effectiveProfile = isAnon ? 'stealth' : profile;
    if (isAnon) {
        const dot = document.getElementById('anon-dot');
        if (dot) { dot.style.background = '#00ff88'; dot.style.boxShadow = '0 0 6px #00ff88'; }
    }

    const params = new URLSearchParams({
        target,
        mode,
        profile: effectiveProfile,
        port_start: $('port-start').value,
        port_end:   $('port-end').value,
        timeout:    $('timeout').value,
        anon:       isAnon ? '1' : '0',
    });

    // Hermetically destroy any existing EventSource before creating a new one
    _destroyEventSource();

    const es = _createEventSource('/api/scan?' + params);

    es.onmessage = e => {
        let d;
        try { d = JSON.parse(e.data); } catch { return; }

        // ── SSRF error from backend ───────────────────────────────────────────
        if (d.error) {
            const statusCode = d.status || 0;
            if (statusCode === 403 || d.error === 'ssrf_blocked') {
                showError(
                    state.lang === 'es'
                        ? '⛔ Escaneo bloqueado — IP interna no permitida. Activa ALLOW_PRIVATE_IPS=true para redes privadas.'
                        : '⛔ Scan blocked — internal IP not allowed. Set ALLOW_PRIVATE_IPS=true for private networks.'
                );
            } else {
                showError(d.error);
            }
            stopScan();
            return;
        }

        if (d.type === 'meta') {
            state.scanMeta = d;
            $('status-target').textContent = (d.hostname && d.hostname !== d.ip)
                ? d.hostname + ' (' + d.ip + ')'
                : d.ip;
            $('st-total').textContent = d.total_ports;
            if (d.geo && Object.keys(d.geo).length) {
                state.geoData = d.geo;
                renderGeo(d.geo);
            }
            return;
        }

        if (d.type === 'port') {
            state.results.push(d);
            state.counts[d.state]++;
            $('st-scanned').textContent    = d.scanned;
            $('st-open').textContent       = state.counts.open;
            $('progress-fill').style.width = d.progress + '%';
            // Only queue the row if it matches the active filter
            if (state.filter === 'all' || state.filter === d.state) appendRow(d);
            updateSummary();
            return;
        }

        if (d.type === 'done') stopScan(true);

        if (d.type === 'cancelled') stopScan(false);
    };

    es.onerror = () => { if (state.scanning) stopScan(); };
}

export function stopScan(completed = false) {
    state.scanning = false;

    // Flush any rows that were queued but not yet rendered (last batch)
    flushAndDrain();

    // Hermetic EventSource teardown — null handlers before close
    _destroyEventSource();

    $('btn-scan').querySelector('.es').textContent = 'Iniciar Escaneo';
    $('btn-scan').querySelector('.en').textContent = 'Start Scan';
    $('btn-scan').style.borderColor = '';
    $('btn-scan').style.color       = '';
    setDotBlink(false);

    if (completed) {
        $('progress-fill').style.width   = '100%';
        $('summary-panel').style.display = 'block';

        if (state.scanMeta) {
            const openPorts = state.results
                .filter(r => r.state === 'open')
                .map(r => ({ port: r.port, service: r.service }));

            saveHistory({
                target:   state.scanMeta.input || state.scanMeta.ip,
                ip:       state.scanMeta.ip,
                mode:     state.scanMeta.mode,
                profile:  state.scanMeta.profile || 'normal',
                open:     state.counts.open,
                total:    state.results.length,
                riskHigh: 0,
                riskMed:  0,
                openPorts,
                date:     new Date().toLocaleString(),
            });
            renderHistory();

            const webPorts = state.results.filter(
                r => r.state === 'open' && [80, 443, 8080, 8443, 8888].includes(r.port)
            );
            if (webPorts.length > 0) {
                $('audit-panel').classList.add('visible');
                launchAudit();

                const firstWebPort     = webPorts[0];
                const screenshotTarget = state.scanMeta.hostname || state.scanMeta.ip;
                fetch(`/api/screenshot/capture?target=${encodeURIComponent(screenshotTarget)}&port=${firstWebPort.port}`, { method: 'POST' })
                    .catch(() => {});
            }
            if (state.counts.open > 0) {
                $('btn-fingerprint').style.display = 'inline-flex';
                $('btn-fingerprint').disabled      = false;
                $('btn-fingerprint').className     = 'btn-fingerprint';
                $('btn-fingerprint').innerHTML     = '🔍 <span class="es">Fingerprinting</span><span class="en">Fingerprint</span>';
            }
        }
    }

    if (!state.results.length) {
        const msg = state.lang === 'es' ? 'Sin resultados' : 'No results found';
        $('results-body').innerHTML = `<tr><td colspan="6"><div class="empty-state">[ _ ]<br>${msg}</div></td></tr>`;
    }
}

// ── Fingerprinting ────────────────────────────────────────────────────────────
export async function runFingerprint() {
    const btn      = $('btn-fingerprint');
    const statusEl = $('fp-status-bar');
    btn.disabled   = true;
    btn.className  = 'btn-fingerprint running';
    btn.innerHTML  = '<span class="spinner"></span><span class="es">Fingerprinting...</span><span class="en">Fingerprinting...</span>';
    statusEl.style.cssText = 'color:var(--text-dim)';

    const openPorts = state.results.filter(r => r.state === 'open').map(r => r.port);
    const target    = state.scanMeta?.input || state.scanMeta?.ip;
    if (!target || !openPorts.length) { btn.disabled = false; statusEl.textContent = ''; return; }

    const dynamicTimeout = NMAP_BASE_TIMEOUT_SEC + NMAP_PER_PORT_SEC * openPorts.length;
    const estMsg = state.lang === 'es'
        ? `⟳ Consultando nmap — estimado ~${dynamicTimeout}s...`
        : `⟳ Querying nmap — estimated ~${dynamicTimeout}s...`;
    statusEl.textContent = estMsg;

    const ctrl    = getController('fingerprint');
    const resetBtn = () => {
        setTimeout(() => {
            btn.disabled  = false;
            btn.className = 'btn-fingerprint';
            btn.innerHTML = '🔍 <span class="es">Fingerprinting</span><span class="en">Fingerprint</span>';
        }, 6000);
    };

    try {
        const resp = await fetch(
            `/api/fingerprint?target=${encodeURIComponent(target)}&ports=${openPorts.join(',')}`,
            { signal: ctrl.signal }
        );
        clearController('fingerprint');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        if (data.error) {
            btn.className = 'btn-fingerprint fp-error'; btn.innerHTML = '⚠ Error';
            statusEl.style.cssText = 'color:#cc3344'; statusEl.textContent = 'Error: ' + data.error;
            resetBtn(); return;
        }

        const results = data.results || {};
        if (results._error === 'nmap_not_installed') {
            btn.className = 'btn-fingerprint fp-error'; btn.innerHTML = '⚠ nmap';
            const isWin = navigator.userAgent.includes('Windows');
            const cmd   = isWin ? 'winget install Insecure.Nmap' : 'sudo apt install nmap';
            statusEl.style.cssText = '';
            statusEl.innerHTML = `<div class="nmap-error-box">⚠ <strong>nmap no está instalado</strong>. ${state.lang === 'es' ? 'Instalar con:' : 'Install with:'} <code>${cmd}</code></div>`;
            resetBtn(); return;
        }

        let updated = 0;
        Object.entries(results).forEach(([portKey, info]) => {
            const p = parseInt(portKey);
            if (isNaN(p)) return;
            const vStr = [info.product, info.version, info.extrainfo].filter(Boolean).join(' ').trim()
                      || info.banner || '';
            if (vStr) { state.versions[p] = { version: vStr, source: 'nmap', cpe: info.cpe || '' }; updated++; }
        });

        import('./ui.js').then(({ renderTable }) => renderTable());
        btn.className = 'btn-fingerprint fp-done';
        btn.innerHTML = '✓ <span class="es">Actualizado</span><span class="en">Updated</span>';
        statusEl.style.cssText = 'color:#00cc66';
        statusEl.textContent = updated > 0
            ? (state.lang === 'es' ? `✓ ${updated} versiones detectadas` : `✓ ${updated} versions detected`)
            : (state.lang === 'es' ? 'nmap no detectó versiones conocidas' : 'nmap could not identify versions');
        setTimeout(() => {
            btn.disabled  = false;
            btn.className = 'btn-fingerprint';
            btn.innerHTML = '🔍 <span class="es">Fingerprinting</span><span class="en">Fingerprint</span>';
            statusEl.style.cssText = ''; statusEl.textContent = '';
        }, 10000);

        launchCVELookup();
    } catch (e) {
        clearController('fingerprint');
        if (e.name === 'AbortError') return;
        btn.className = 'btn-fingerprint fp-error'; btn.innerHTML = '⚠ Timeout';
        statusEl.style.cssText = 'color:#cc3344';
        statusEl.textContent = (state.lang === 'es' ? 'Error: ' : 'Error: ') + e.message;
        resetBtn();
    }
}

// ── Full Audit ────────────────────────────────────────────────────────────────
export async function launchAudit() {
    const target = state.scanMeta?.input || state.scanMeta?.ip;
    if (!target) return;

    const openPorts = state.results.filter(r => r.state === 'open').map(r => r.port).join(',');
    const statusEl  = $('audit-status');
    statusEl.innerHTML = '<span class="spinner"></span><span class="es">Analizando...</span><span class="en">Analyzing...</span>';

    const allPanes = ['headers', 'technologies', 'paths', 'ssl', 'cve'];
    const texts    = {
        headers:      { es: 'Auditando cabeceras HTTP...',    en: 'Auditing HTTP headers...' },
        technologies: { es: 'Detectando tecnologías...',      en: 'Detecting technologies...' },
        paths:        { es: 'Escaneando rutas sensibles...',  en: 'Scanning sensitive paths...' },
        ssl:          { es: 'Analizando SSL/TLS...',          en: 'Analyzing SSL/TLS...' },
        cve:          { es: 'Buscando CVEs conocidos...',     en: 'Searching known CVEs...' },
    };
    allPanes.forEach(p => {
        $('pane-' + p).innerHTML = `<div class="audit-loading"><span class="spinner"></span>${state.lang === 'es' ? texts[p].es : texts[p].en}</div>`;
    });

    const sslPorts = state.results
        .filter(r => r.state === 'open' && [443, 8443].includes(r.port))
        .map(r => r.port);

    const auditCtrl = getController('audit');
    const sslCtrl   = getController('ssl');

    const auditFetch = fetch(
        `/api/audit?target=${encodeURIComponent(target)}&open_ports=${encodeURIComponent(openPorts)}`,
        { signal: auditCtrl.signal }
    ).then(r => r.json()).catch(e => (e.name === 'AbortError' ? null : null));

    const sslFetch = sslPorts.length > 0
        ? fetch(
            `/api/ssl?target=${encodeURIComponent(target)}&open_ports=${encodeURIComponent(sslPorts.join(','))}`,
            { signal: sslCtrl.signal }
          ).then(r => r.json()).catch(e => (e.name === 'AbortError' ? null : null))
        : Promise.resolve(null);

    try {
        const [auditData, sslData] = await Promise.all([auditFetch, sslFetch]);
        clearController('audit');
        clearController('ssl');

        if (auditData) { state.auditData = auditData; renderAudit(auditData); }
        else {
            allPanes.slice(0, 3).forEach(p => {
                $('pane-' + p).innerHTML = `<div class="no-results">⚠ ${state.lang === 'es' ? 'Error al conectar' : 'Connection error'}</div>`;
            });
        }
        renderSSLAudit(sslData);
        renderCVEPlaceholder();
        statusEl.textContent = '';
    } catch {
        clearController('audit');
        clearController('ssl');
        statusEl.textContent = state.lang === 'es' ? 'Error en auditoría' : 'Audit error';
    }
}

// ── CVE Lookup ────────────────────────────────────────────────────────────────
export async function launchCVELookup() {
    const pane      = $('pane-cve');
    const openPorts = state.results.filter(r => r.state === 'open');

    pane.innerHTML = tmplCVELoading(state.lang, openPorts.length);

    if (!openPorts.length) {
        pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang === 'es' ? 'Sin puertos abiertos' : 'No open ports'}</div>`;
        return;
    }

    const versionsPayload = {};
    openPorts.forEach(r => {
        const v = state.versions[r.port];
        if (v?.version) versionsPayload[r.port] = { name: r.service, version: v.version };
        else if (r.service && r.service !== 'Unknown') versionsPayload[r.port] = { name: r.service, version: '' };
    });

    if (!Object.keys(versionsPayload).length) {
        pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang === 'es' ? 'Ejecuta Fingerprinting primero' : 'Run Fingerprinting first for better results'}</div>`;
        return;
    }

    const ctrl = getController('cve');

    try {
        const resp = await fetch('/api/cve/batch', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(versionsPayload),
            signal:  ctrl.signal,
        });
        clearController('cve');
        const data = await resp.json();
        renderCVEAudit(data.results || {}, versionsPayload);
    } catch (e) {
        clearController('cve');
        if (e.name === 'AbortError') return;
        pane.innerHTML = `<div class="no-results">⚠ ${state.lang === 'es' ? 'No se pudo conectar con NVD' : 'Could not connect to NVD'}</div>`;
    }
}

// ── Network Discovery ─────────────────────────────────────────────────────────
export async function launchDiscover() {
    const cidr   = $('discover-cidr')?.value?.trim();
    const output = $('discover-output');
    if (!cidr || !output) return;

    const btn = $('btn-discover');
    if (btn) { btn.disabled = true; btn.textContent = state.lang === 'es' ? 'Escaneando...' : 'Scanning...'; }
    output.innerHTML = `<div class="audit-loading"><span class="spinner"></span>${state.lang === 'es' ? 'Escaneando red...' : 'Scanning network...'}</div>`;

    const ctrl = getController('discover');

    try {
        const resp = await fetch(`/api/discover?cidr=${encodeURIComponent(cidr)}`, { signal: ctrl.signal });
        clearController('discover');
        const data = await resp.json();

        if (data.error) {
            output.innerHTML = `<div class="no-results">⚠ ${data.error}</div>`;
            return;
        }
        output.innerHTML = tmplDiscoverOutput(data, cidr, state.lang);
    } catch (e) {
        clearController('discover');
        if (e.name === 'AbortError') return;
        output.innerHTML = `<div class="no-results">⚠ ${e.message}</div>`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = state.lang === 'es' ? 'Descubrir' : 'Discover'; }
    }
}

// ── Subdomain Enumeration ─────────────────────────────────────────────────────
export async function launchSubdomains() {
    const domain = $('subdomain-input')?.value?.trim();
    const output = $('subdomain-output');
    if (!domain || !output) return;

    const btn = $('btn-subdomains');
    if (btn) { btn.disabled = true; btn.textContent = state.lang === 'es' ? 'Buscando...' : 'Searching...'; }
    output.innerHTML = `<div class="audit-loading"><span class="spinner"></span>${state.lang === 'es' ? 'Consultando crt.sh...' : 'Querying crt.sh...'}</div>`;

    const ctrl = getController('subdomains');

    try {
        const resp = await fetch(`/api/subdomains?domain=${encodeURIComponent(domain)}`, { signal: ctrl.signal });
        clearController('subdomains');
        const data = await resp.json();

        if (data.error) {
            output.innerHTML = `<div class="no-results">⚠ ${data.error}</div>`;
            return;
        }
        output.innerHTML = tmplSubdomainsOutput(data, domain, state.lang);
    } catch (e) {
        clearController('subdomains');
        if (e.name === 'AbortError') return;
        output.innerHTML = `<div class="no-results">⚠ ${e.message}</div>`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = state.lang === 'es' ? 'Buscar Subdominios' : 'Find Subdomains'; }
    }
}
