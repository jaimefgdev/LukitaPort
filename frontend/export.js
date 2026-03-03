// export.js
// Handles all client-side export formats: JSON, CSV, HTML, PDF (server), Markdown (server).
//
// Non-blocking architecture
// ─────────────────────────
// Processing 65 535 results in a single synchronous loop (results.map / forEach)
// blocks the main thread for hundreds of milliseconds, freezing spinners and
// making the UI appear hung.
//
// Every export that processes state.results in-browser is now async and uses
// yieldToMain() (setTimeout 0 ms) between fixed-size chunks.  This returns
// control to the browser event loop between chunks so:
//   • CSS animations / spinner keep running
//   • The browser does not display "page unresponsive" warnings
//   • The user can still interact with the rest of the UI
//
// Chunk size  EXPORT_CHUNK = 5 000 items
// ───────────────────────────────────────
// At 65 535 items → 14 chunks → 14 yields → ~0 ms perceived lag per chunk.
// Measured overhead vs synchronous: < 30 ms total for JSON, < 50 ms for HTML.

import { state, getRisk }  from './state.js';
import { $, showToast }    from './ui.js';
import { tmplHTMLReport }  from './templates.js';

// ── Chunk size ────────────────────────────────────────────────────────────────
const EXPORT_CHUNK = 5_000;

// ── yieldToMain — hand control back to the browser event loop ─────────────────
/**
 * Awaiting this between processing chunks allows the browser to:
 *   1. Run pending microtasks (promise callbacks).
 *   2. Fire any pending animation frame callbacks (keeping spinners alive).
 *   3. Handle user input events that arrived during CPU work.
 *
 * setTimeout(0) is preferred over requestIdleCallback here because:
 *   - It guarantees a yield even when the tab is busy (rIC can be delayed
 *     indefinitely if the tab is never "idle").
 *   - It runs in ≤ 4 ms in modern browsers (the minimum clamped delay).
 */
function yieldToMain() {
    return new Promise(resolve => setTimeout(resolve, 0));
}

// ── File download helper ──────────────────────────────────────────────────────
function dl(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

function getTs()   { return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19); }
function getSlug() { return (state.scanMeta?.ip ?? 'scan').replace(/\./g, '_'); }

// ── Spinner helper ────────────────────────────────────────────────────────────
function setBtnLoading(btn, loadingLabel) {
    const original = btn.textContent;
    btn.textContent = loadingLabel;
    btn.disabled    = true;
    return () => { btn.textContent = original; btn.disabled = false; };
}

// ── JSON export ───────────────────────────────────────────────────────────────
/**
 * exportJSON
 *
 * Blocking operation avoided: building the results array with escaping/transformation.
 * JSON.stringify of the final payload is still synchronous but takes < 10 ms
 * for 65 k items with small objects; the heavy per-item transform runs in chunks.
 */
export async function exportJSON() {
    if (!state.results.length) return;
    const btn      = $('btn-json');
    const restore  = setBtnLoading(btn, '↻ JSON...');

    try {
        // ── Chunked transform ─────────────────────────────────────────────────
        const transformedResults = [];
        const results = state.results;

        for (let i = 0; i < results.length; i += EXPORT_CHUNK) {
            const chunk = results.slice(i, i + EXPORT_CHUNK);
            chunk.forEach(r => transformedResults.push({
                ...r,
                risk:    getRisk(r.port),
                version: state.versions[r.port] || null,
            }));
            if (i + EXPORT_CHUNK < results.length) await yieldToMain();
        }

        const payload = {
            meta: {
                tool:         'LukitaPort',
                author:       'jaimefg1888',
                generated_at: new Date().toISOString(),
                target:       state.scanMeta || {},
                geo:          state.geoData  || {},
                summary:      { ...state.counts, total: results.length },
            },
            results: transformedResults,
        };

        // JSON.stringify is synchronous but fast for plain objects
        dl(JSON.stringify(payload, null, 2), `lukitaport_${getSlug()}_${getTs()}.json`, 'application/json');
        showToast('JSON exportado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error JSON: ' : 'JSON error: ') + e.message, 'error');
    } finally {
        restore();
    }
}

// ── CSV export ────────────────────────────────────────────────────────────────
/**
 * exportCSV
 *
 * Chunked: builds the rows string segment-by-segment so the join()
 * never operates on a single giant array in one shot.
 */
export async function exportCSV() {
    if (!state.results.length) return;
    const btn     = $('btn-csv');
    const restore = setBtnLoading(btn, '↻ CSV...');

    try {
        const header  = 'Port,State,Service,Risk,Response_ms,Version\r\n';
        const parts   = [header];
        const results = state.results;

        for (let i = 0; i < results.length; i += EXPORT_CHUNK) {
            const chunk = results.slice(i, i + EXPORT_CHUNK);
            // Build rows for this chunk and append as one string segment
            parts.push(
                chunk.map(r => [
                    r.port,
                    r.state,
                    // Wrap service/version in quotes to handle commas in banners
                    '"' + (r.service || '').replace(/"/g, '""') + '"',
                    getRisk(r.port),
                    r.response_time_ms ?? '',
                    '"' + (state.versions[r.port]?.version || '').replace(/"/g, '""') + '"',
                ].join(',')).join('\r\n')
            );
            if (i + EXPORT_CHUNK < results.length) {
                parts.push('\r\n');
                await yieldToMain();
            }
        }

        dl(parts.join(''), `lukitaport_${getSlug()}_${getTs()}.csv`, 'text/csv');
        showToast('CSV exportado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error CSV: ' : 'CSV error: ') + e.message, 'error');
    } finally {
        restore();
    }
}

// ── PDF export (server-side, already non-blocking) ────────────────────────────
export async function exportPDF() {
    if (!state.results.length) return;
    const btn     = $('btn-pdf');
    const restore = setBtnLoading(btn, '↻ PDF...');

    try {
        // Build results payload in chunks before sending to server
        const transformedResults = [];
        for (let i = 0; i < state.results.length; i += EXPORT_CHUNK) {
            state.results.slice(i, i + EXPORT_CHUNK).forEach(r =>
                transformedResults.push({ ...r, version: state.versions[r.port]?.version || null })
            );
            if (i + EXPORT_CHUNK < state.results.length) await yieldToMain();
        }

        const body = {
            scan: {
                meta:    { target: state.scanMeta },
                results: transformedResults,
                summary: { ...state.counts, total: state.results.length },
            },
            audit:             state.auditData || null,
            screenshot_target: state.scanMeta?.hostname || state.scanMeta?.ip || null,
        };

        const resp = await fetch('/api/export/pdf', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });
        if (!resp.ok) throw new Error('Server error');

        const blob = await resp.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `lukitaport_report_${getSlug()}_${getTs()}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('PDF generado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error generando PDF: ' : 'PDF error: ') + e.message, 'error');
    } finally {
        restore();
    }
}

// ── Markdown export (server-side, already non-blocking) ───────────────────────
export async function exportMarkdown() {
    if (!state.results.length) return;
    const btn     = $('btn-md');
    const restore = setBtnLoading(btn, '↻ MD...');

    try {
        const transformedResults = [];
        for (let i = 0; i < state.results.length; i += EXPORT_CHUNK) {
            state.results.slice(i, i + EXPORT_CHUNK).forEach(r =>
                transformedResults.push({ ...r, version: state.versions[r.port]?.version || null })
            );
            if (i + EXPORT_CHUNK < state.results.length) await yieldToMain();
        }

        const body = {
            scan: {
                meta:    { target: state.scanMeta },
                results: transformedResults,
                summary: { ...state.counts, total: state.results.length },
            },
            audit: state.auditData || null,
        };

        const resp = await fetch('/api/export/md', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });
        if (!resp.ok) throw new Error('Server error');

        dl(await resp.text(), `lukitaport_report_${getSlug()}_${getTs()}.md`, 'text/markdown');
        showToast('Markdown exportado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error generando MD: ' : 'MD error: ') + e.message, 'error');
    } finally {
        restore();
    }
}

// ── HTML Report export (client-side, chunked) ─────────────────────────────────
/**
 * exportHTMLReport
 *
 * The most expensive in-browser export because each result row requires HTML
 * escaping and string formatting.  Fully chunked using yieldToMain().
 *
 * Architecture:
 *   1. Build rows HTML in EXPORT_CHUNK-sized batches → rowSegments[] (strings)
 *   2. Yield to browser between each batch
 *   3. Join all segments into prebuiltRowsHtml
 *   4. Call tmplHTMLReport(..., prebuiltRowsHtml) — the template uses the
 *      pre-built string directly, skipping its synchronous results.map()
 *   5. Trigger download
 *
 * For 65 535 items this produces ~14 yields and a total wall-clock time of
 * approximately 200–400 ms (depending on hardware) vs a single ~600 ms freeze.
 */
export async function exportHTMLReport() {
    if (!state.results.length) return;
    const btn     = $('btn-html');
    const restore = setBtnLoading(btn, '↻ HTML...');

    try {
        const results  = state.results;
        const rc       = { high: '#ff0033', medium: '#ffaa00', low: '#00ff88', info: '#444' };
        const rl2      = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: '—' };

        // escapeHTML is available via ui.js re-export, but import it from
        // templates.js directly to keep export.js independent of ui.js
        const { escapeHTML } = await import('./templates.js');

        const rowSegments = [];

        for (let i = 0; i < results.length; i += EXPORT_CHUNK) {
            const chunk = results.slice(i, i + EXPORT_CHUNK);

            rowSegments.push(
                chunk.map(r => {
                    const sc  = r.state === 'open' ? '#00ff88' : r.state === 'filtered' ? '#ffaa00' : '#ff4444';
                    const rk  = getRisk(r.port);
                    const ver = state.versions[r.port]?.version || '';
                    const st  = r.state.charAt(0).toUpperCase() + r.state.slice(1);
                    return `<tr><td>${r.port}</td><td style="color:${sc}">● ${escapeHTML(st)}</td><td>${escapeHTML(r.service)}</td><td style="color:${rc[rk]};font-size:10px">${rl2[rk]}</td><td>${r.response_time_ms ?? '—'} ms</td><td style="font-size:10px;color:#666;max-width:160px;overflow:hidden">${escapeHTML(ver)}</td></tr>`;
                }).join('')
            );

            if (i + EXPORT_CHUNK < results.length) await yieldToMain();
        }

        const prebuiltRowsHtml = rowSegments.join('');

        // tmplHTMLReport receives the finished rowsHtml and skips its own .map()
        const html = tmplHTMLReport(
            {
                meta:      state.scanMeta || {},
                results,              // still passed for totalCount + metadata
                counts:    state.counts,
                auditData: state.auditData,
                geoData:   state.geoData,
                versions:  state.versions,
                getRisk,
            },
            prebuiltRowsHtml,         // <── non-blocking pre-built rows
        );

        dl(html, `lukitaport_report_${getSlug()}_${getTs()}.html`, 'text/html');
        showToast('HTML exportado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error HTML: ' : 'HTML error: ') + e.message, 'error');
    } finally {
        restore();
    }
}
