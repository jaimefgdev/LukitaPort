// templates.js
// Pure HTML template functions. No DOM access — receive data, return HTML strings.
// Imported by ui.js, export.js, and api.js.
//
// ── CSP compliance ────────────────────────────────────────────────────────────
// This module contains ZERO inline event handlers (onclick, onmouseover, etc.).
// Every interactive element uses data-action + data-* attributes.
// A single event delegate in main.js intercepts all clicks on the body.
//
// data-action contract (complete registry)
// ─────────────────────────────────────────
//   "copy"        + data-copy-text="{text}"       → copy text to clipboard
//   "launch-cve"                                   → run CVE batch lookup
//   "scan-host"   + data-host="{ip|hostname}"      → load into target input
//
// Hover for .btn-cve-launch is handled purely by CSS class injected once by
// initDelegationStyles() in ui.js (no JS onmouseover/onmouseout).
//
// ── Non-blocking exports ──────────────────────────────────────────────────────
// tmplHTMLReport(opts, prebuiltRowsHtml?)
//   When export.js passes prebuiltRowsHtml (built asynchronously in chunks),
//   the synchronous results.map() inside this function is skipped entirely,
//   keeping the main thread free.

// ─────────────────────────────────────────────────────────────────────────────
// Security utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * escapeHTML — convert the five dangerous chars to HTML entities.
 * Apply to EVERY backend string before injecting into innerHTML.
 */
export function escapeHTML(s) {
    if (s === null || s === undefined) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/** safeHref — reject javascript:, data:, vbscript: URLs. */
function safeHref(url) {
    if (!url || typeof url !== 'string') return '#';
    if (/^(javascript|data|vbscript):/i.test(url.trim())) return '#';
    return url;
}

/** safeSev — whitelist CSS severity class suffixes. */
const VALID_SEV = new Set(['high', 'medium', 'low', 'info', 'critical']);
const safeSev   = s => VALID_SEV.has(s) ? s : 'info';

// ── Constants ─────────────────────────────────────────────────────────────────

const HEADER_EXAMPLES = {
    'Strict-Transport-Security': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy':   "Content-Security-Policy: default-src 'self'; script-src 'self'",
    'X-Frame-Options':           'X-Frame-Options: SAMEORIGIN',
    'X-Content-Type-Options':    'X-Content-Type-Options: nosniff',
    'Referrer-Policy':           'Referrer-Policy: strict-origin-when-cross-origin',
    'Permissions-Policy':        'Permissions-Policy: camera=(), microphone=(), geolocation=()',
    'X-XSS-Protection':          'X-XSS-Protection: 1; mode=block',
};

const HEADER_NGINX = {
    'Strict-Transport-Security': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    'Content-Security-Policy':   "add_header Content-Security-Policy \"default-src 'self'\" always;",
    'X-Frame-Options':           'add_header X-Frame-Options "SAMEORIGIN" always;',
    'X-Content-Type-Options':    'add_header X-Content-Type-Options "nosniff" always;',
    'Referrer-Policy':           'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    'Permissions-Policy':        'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
    'X-XSS-Protection':          'add_header X-XSS-Protection "1; mode=block" always;',
};

const GRADE_COLOR = {
    'A+': '#00ff88', A: '#00ff88', B: '#44cc88',
    C:    '#ffaa00', D: '#ff6600', F: '#ff0033',
};

// ── Headers Audit ─────────────────────────────────────────────────────────────

export function tmplHeadersAudit(d, lang) {
    if (!d || d.error) return `<div class="no-results">⚠ ${escapeHTML(d?.error || 'No data')}</div>`;

    const gc = GRADE_COLOR[d.grade] || '#888';
    const gradeLabelEs = { A: 'Excelente', 'A+': 'Perfecto', B: 'Bueno', C: 'Mejorable', D: 'Deficiente', F: 'Suspenso' };
    const gradeLabelEn = { A: 'Excellent',  'A+': 'Perfect',  B: 'Good',  C: 'Needs work', D: 'Poor',      F: 'Failing' };

    const sevLabel = s => {
        const safe = safeSev(s);
        return lang === 'es'
            ? ({ high: 'ALTO', medium: 'MEDIO', low: 'BAJO' }[safe] || safe.toUpperCase())
            : safe.toUpperCase();
    };

    const missingHigh = (d.missing || []).filter(h => h.severity === 'high').length;
    const missingMed  = (d.missing || []).filter(h => h.severity === 'medium').length;
    const missingLow  = (d.missing || []).filter(h => h.severity === 'low').length;

    let html = `
    <div class="grade-row">
        <div class="grade-badge grade-${escapeHTML(d.grade)}">${escapeHTML(d.grade)}</div>
        <div class="grade-info">
            <div style="font-family:var(--font-mono);font-size:16px;color:${gc};font-weight:700">${lang === 'es' ? 'Puntuación' : 'Score'}: ${d.score}/100 — ${lang === 'es' ? gradeLabelEs[d.grade] : gradeLabelEn[d.grade]}</div>
            <div class="grade-score">${d.present?.length || 0} ${lang === 'es' ? 'cabeceras correctas' : 'headers present'} · ${d.missing?.length || 0} ${lang === 'es' ? 'ausentes' : 'missing'}</div>
            <div class="grade-url">${escapeHTML(d.url)}</div>
        </div>
    </div>
    <div class="audit-stat-bar">
        <div class="asb-item"><div class="asb-dot" style="background:#ff0033"></div><span class="asb-label">${lang === 'es' ? 'Alto' : 'High'}</span><span class="asb-num" style="color:#ff0033">${missingHigh}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#ffaa00"></div><span class="asb-label">${lang === 'es' ? 'Medio' : 'Medium'}</span><span class="asb-num" style="color:#ffaa00">${missingMed}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00bb66"></div><span class="asb-label">${lang === 'es' ? 'Bajo' : 'Low'}</span><span class="asb-num" style="color:#00bb66">${missingLow}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">${lang === 'es' ? 'Presentes' : 'Present'}</span><span class="asb-num" style="color:#aaa">${d.present?.length || 0}</span></div>
    </div>`;

    if (d.missing?.length) {
        html += `<div class="subsection-label">⚠ ${lang === 'es' ? 'Cabeceras ausentes' : 'Missing headers'} (${d.missing.length})</div>`;
        d.missing.forEach(h => {
            const example   = HEADER_EXAMPLES[h.header] || '';
            const nginx     = HEADER_NGINX[h.header]    || '';
            const copyValue = nginx || example;
            const sev       = safeSev(h.severity);

            // ── CSP-safe copy button: data-action="copy" data-copy-text="…" ───
            const copyBtn = example
                ? `<button class="copy-btn"
                           style="position:absolute;top:5px;right:7px"
                           data-action="copy"
                           data-copy-text="${escapeHTML(copyValue)}"
                   >${lang === 'es' ? 'Copiar nginx' : 'Copy nginx'}</button>`
                : '';

            html += `
            <div class="missing-header-card sev-${sev}-card">
                <div class="mhc-top">
                    <div class="mhc-name">${escapeHTML(h.header)}</div>
                    <span class="sev-badge sev-${sev}">${sevLabel(h.severity)}</span>
                </div>
                <div class="mhc-desc">${escapeHTML(lang === 'es' ? h.description_es : h.description_en)}</div>
                ${example ? `
                <div class="mhc-example-label">${lang === 'es' ? 'Añadir a tu servidor:' : 'Add to your server:'}</div>
                <div class="mhc-example">${escapeHTML(example)}${copyBtn}</div>` : ''}
            </div>`;
        });
    }

    if (d.present?.length) {
        html += `<div class="subsection-label" style="margin-top:20px">✓ ${lang === 'es' ? 'Cabeceras presentes' : 'Present headers'} (${d.present.length})</div>`;
        d.present.forEach(h => {
            html += `<div class="present-header-card"><div class="phc-top"><div><div class="phc-name">✓ ${escapeHTML(h.header)}</div><div class="phc-val">${escapeHTML(h.value)}</div></div></div></div>`;
        });
    }

    if (d.dangerous?.length) {
        html += `<div class="subsection-label" style="margin-top:20px;color:#ffaa00">⚠ ${lang === 'es' ? 'Cabeceras que revelan información' : 'Information disclosure headers'}</div>`;
        d.dangerous.forEach(h => {
            const copyVal = h.header + ': ' + h.value;
            // ── CSP-safe copy button ───────────────────────────────────────────
            html += `
            <div class="danger-card">
                <div class="danger-card-top">
                    <span class="danger-card-key">${escapeHTML(h.header)}:</span>
                    <span class="danger-card-val">${escapeHTML(h.value)}</span>
                    <button class="copy-btn"
                            style="margin-left:auto"
                            data-action="copy"
                            data-copy-text="${escapeHTML(copyVal)}"
                    >${lang === 'es' ? 'Copiar' : 'Copy'}</button>
                </div>
                <div class="danger-card-desc">${escapeHTML(h.description)}</div>
                <div class="danger-card-tip">💡 ${lang === 'es' ? 'Eliminar con nginx: ' : 'Remove with nginx: '}<code style="color:#ffcc77">server_tokens off;</code></div>
            </div>`;
        });
    }

    return html;
}

// ── Technology Audit ─────────────────────────────────────────────────────────

export function tmplTechAudit(d, lang) {
    if (!d || d.error) return `<div class="no-results">⚠ ${escapeHTML(d?.error || 'No data')}</div>`;
    if (!d.technologies?.length) return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se detectaron tecnologías' : 'No technologies detected'}</div>`;

    const cats = d.by_category || {};
    let html = '';
    Object.entries(cats).forEach(([cat, techs]) => {
        html += `<div class="subsection-label">${escapeHTML(cat)}</div><div class="tech-list">`;
        techs.forEach(t => {
            html += `<div class="tech-row"><span class="tech-icon-sm">${escapeHTML(t.icon)}</span><span class="tech-name-sm">${escapeHTML(t.name)}</span><span class="tech-cat-sm">${escapeHTML(t.category)}</span></div>`;
        });
        html += '</div>';
    });
    return html;
}

// ── Paths Audit ───────────────────────────────────────────────────────────────

export function tmplPathsAudit(d, lang) {
    if (!d) return '<div class="no-results">No data</div>';
    if (!d.found?.length) return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron rutas sensibles' : 'No sensitive paths found'}</div>`;

    const sevLabel = s => {
        const safe = safeSev(s);
        return lang === 'es'
            ? ({ high: 'ALTO', medium: 'MEDIO', info: 'INFO' }[safe] || safe.toUpperCase())
            : safe.toUpperCase();
    };

    const highAll = d.found.filter(f => f.severity === 'high').length;
    const medAll  = d.found.filter(f => f.severity === 'medium').length;
    const acc200  = d.found.filter(f => f.accessible).length;
    const rest403 = d.found.filter(f => !f.accessible && f.status_code === 403).length;

    let html = `
    <div class="audit-stat-bar">
        <div class="asb-item"><div class="asb-dot" style="background:#ff0033"></div><span class="asb-label">${lang === 'es' ? 'Alto riesgo' : 'High risk'}</span><span class="asb-num" style="color:#ff0033">${highAll}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#ffaa00"></div><span class="asb-label">${lang === 'es' ? 'Riesgo medio' : 'Medium risk'}</span><span class="asb-num" style="color:#ffaa00">${medAll}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">200 OK</span><span class="asb-num" style="color:#00ff88">${acc200}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">403</span><span class="asb-num" style="color:#888">${rest403}</span></div>
    </div>`;

    const descFor = f => escapeHTML(
        lang === 'es'
            ? (f.description.split('/')[0] || f.label).trim()
            : (f.description.split('/')[1] || f.description).trim()
    );

    const accessible = d.found.filter(f => f.accessible);
    const others     = d.found.filter(f => !f.accessible);

    if (accessible.length) {
        html += `<div class="subsection-label" style="color:#ff5533">🔴 ${lang === 'es' ? 'Accesibles públicamente' : 'Publicly accessible'} (${accessible.length})</div>`;
        accessible.forEach(f => {
            const sev = safeSev(f.severity);
            // ── CSP-safe URL copy button ───────────────────────────────────────
            html += `
            <div class="path-card pc-${sev}">
                <div class="path-card-status pcs-${f.status_code}">${f.status_code}</div>
                <div class="path-card-body">
                    <div class="path-card-url">${escapeHTML(f.path)}</div>
                    <div class="path-card-label">${escapeHTML(f.label)}</div>
                    <div class="path-card-desc">${descFor(f)}</div>
                </div>
                <div class="path-card-right">
                    <span class="path-status-tag pst-${sev}">${sevLabel(f.severity)}</span>
                    <button class="path-copy-btn"
                            data-action="copy"
                            data-copy-text="${escapeHTML(f.url)}"
                    >${lang === 'es' ? 'Copiar URL' : 'Copy URL'}</button>
                </div>
            </div>`;
        });
    }

    if (others.length) {
        html += `<div class="subsection-label" style="margin-top:24px">🔒 ${lang === 'es' ? 'Existen pero bloqueadas' : 'Exist but blocked'} (${others.length})</div>`;
        others.forEach(f => {
            const sev = safeSev(f.severity);
            html += `
            <div class="path-card" style="opacity:.75">
                <div class="path-card-status pcs-${f.status_code}">${f.status_code}</div>
                <div class="path-card-body">
                    <div class="path-card-url">${escapeHTML(f.path)}</div>
                    <div class="path-card-label">${escapeHTML(f.label)}</div>
                </div>
                <div class="path-card-right">
                    <span class="path-status-tag ${sev === 'high' ? 'pst-medium' : 'pst-info'}">${sevLabel(f.severity)}</span>
                </div>
            </div>`;
        });
    }

    return html;
}

// ── SSL Audit ─────────────────────────────────────────────────────────────────

export function tmplSSLAudit(data, lang) {
    if (!data || data.error) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'Sin puertos HTTPS detectados' : 'No HTTPS ports detected'}</div>`;
    }
    const results = data.results || {};
    if (!Object.keys(results).length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'Sin datos SSL' : 'No SSL data'}</div>`;
    }

    const gradeColor = {
        'A+': '#00ff88', A: '#00ff88', B: '#44cc88',
        C:    '#ffaa00', D: '#ff6600', F: '#ff0033',
    };
    let html = '';

    Object.entries(results).forEach(([port, ssl]) => {
        const gc = gradeColor[ssl.grade] || '#888';
        html += `
        <div style="background:#070707;border:1px solid #1e1e1e;border-radius:4px;padding:20px;margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px">
                <div style="width:52px;height:52px;border-radius:4px;border:1px solid ${gc}33;background:${gc}11;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-size:1.6rem;font-weight:700;color:${gc}">${escapeHTML(ssl.grade)}</div>
                <div>
                    <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:#f0f0f0">${escapeHTML(ssl.hostname)}:${escapeHTML(String(port))}</div>
                    <div style="font-family:var(--font-mono);font-size:11px;color:#888;margin-top:4px">${escapeHTML(ssl.protocol || 'TLS')} · ${escapeHTML(ssl.cipher || '—')} · ${ssl.bits || '?'} bits</div>
                </div>
            </div>`;

        if (ssl.error) {
            html += `<div style="color:#ff5544;font-family:var(--font-mono);font-size:12px">⚠ ${escapeHTML(ssl.error)}</div></div>`;
            return;
        }

        html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">`;
        const sub = ssl.subject || {};
        const iss = ssl.issuer  || {};
        [
            [lang === 'es' ? 'Emisor'        : 'Issuer',      iss.organizationName || iss.commonName || '—'],
            [lang === 'es' ? 'Dominio (CN)'  : 'Common Name', sub.commonName || '—'],
            ['Not Before', ssl.not_before ? ssl.not_before.slice(0, 10) : '—'],
            ['Not After',  ssl.not_after  ? ssl.not_after.slice(0, 10)  : '—'],
            [lang === 'es' ? 'Días restantes' : 'Days left',  ssl.days_until_expiry !== null ? ssl.days_until_expiry + 'd' : '—'],
            [lang === 'es' ? 'Autofirmado'   : 'Self-signed', ssl.self_signed ? '⚠ Yes' : '✓ No'],
        ].forEach(([k, v]) => {
            const isWarn = (k.includes('restante') || k.includes('left')) && ssl.expiring_soon;
            const isErr  = (k.includes('restante') || k.includes('left')) && ssl.expired;
            const vc     = isErr ? '#ff3344' : isWarn ? '#ffaa00' : '#c0c0c0';
            html += `<div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:3px;padding:10px 12px"><div style="font-family:var(--font-mono);font-size:9px;color:#555;letter-spacing:1px;text-transform:uppercase;margin-bottom:3px">${escapeHTML(String(k))}</div><div style="font-family:var(--font-mono);font-size:12px;color:${vc};word-break:break-all">${escapeHTML(String(v))}</div></div>`;
        });
        html += '</div>';

        if (ssl.tls_versions_offered?.length) {
            const verTags = ssl.tls_versions_offered.map(v => {
                const dep = ['TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2'].includes(v);
                const col = dep ? '#ff8866' : '#00cc66';
                return `<span style="font-family:var(--font-mono);font-size:11px;color:${col};background:${col}11;border:1px solid ${col}33;padding:2px 8px;border-radius:3px">${escapeHTML(v)}</span>`;
            }).join('');
            html += `<div style="margin-bottom:12px"><div style="font-family:var(--font-mono);font-size:9px;color:#555;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">${lang === 'es' ? 'Versiones TLS aceptadas' : 'TLS versions offered'}</div><div style="display:flex;flex-wrap:wrap;gap:5px">${verTags}</div></div>`;
        }

        if (ssl.sans?.length) {
            const sanTags = ssl.sans.slice(0, 8).map(s => `<span style="font-family:var(--font-mono);font-size:11px;color:#8899ff;background:rgba(100,100,255,.08);border:1px solid rgba(100,100,255,.15);padding:2px 8px;border-radius:3px">${escapeHTML(s)}</span>`).join('');
            const more    = ssl.sans.length > 8 ? `<span style="color:#555;font-size:11px;font-family:var(--font-mono)">+${ssl.sans.length - 8} more</span>` : '';
            html += `<div style="margin-bottom:12px"><div style="font-family:var(--font-mono);font-size:9px;color:#555;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">Subject Alternative Names (${ssl.sans.length})</div><div style="display:flex;flex-wrap:wrap;gap:5px">${sanTags}${more}</div></div>`;
        }

        if (ssl.issues?.length) {
            html += `<div style="background:rgba(255,0,51,.04);border:1px solid rgba(255,0,51,.15);border-radius:3px;padding:10px 14px">${ssl.issues.map(i => `<div style="font-family:var(--font-mono);font-size:11px;color:#ff5544;margin-bottom:3px">⚠ ${escapeHTML(i)}</div>`).join('')}</div>`;
        } else {
            html += `<div style="color:#00cc66;font-family:var(--font-mono);font-size:11px">✓ ${lang === 'es' ? 'Sin problemas detectados' : 'No issues detected'}</div>`;
        }
        html += '</div>';
    });

    return html;
}

// ── CVE Audit ─────────────────────────────────────────────────────────────────

export function tmplCVEAudit(results, versionsPayload, lang) {
    const ports = Object.keys(results);
    if (!ports.length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron CVEs conocidos para los servicios detectados' : 'No known CVEs found for detected services'}</div>`;
    }

    const sevColor = { CRITICAL: '#ff0033', HIGH: '#ff4444', MEDIUM: '#ffaa00', LOW: '#00cc66', NONE: '#555' };
    const sevLabel = { CRITICAL: 'CRÍTICO', HIGH: 'ALTO', MEDIUM: 'MEDIO', LOW: 'BAJO', NONE: 'NINGUNO' };
    let totalCVEs = 0;

    let html = `<div style="font-family:var(--font-mono);font-size:11px;color:#555;margin-bottom:16px;padding:10px 14px;background:#070707;border:1px solid #161616;border-radius:3px">${lang === 'es' ? 'Fuente: NVD (nvd.nist.gov) · Ejecuta Fingerprinting primero para resultados precisos.' : 'Source: NVD (nvd.nist.gov) · Run Fingerprinting first for precise results.'}</div>`;

    ports.forEach(port => {
        const r       = results[port];
        const meta    = versionsPayload[port] || {};
        const cves    = r.cves || [];
        totalCVEs    += cves.length;
        const keyword = r.keyword_used || `${meta.name || ''} ${meta.version || ''}`.trim();
        const totalLbl = lang === 'es' ? 'CVEs totales' : 'total CVEs';

        const verBadge = meta.version
            ? `<span style="font-family:var(--font-mono);font-size:11px;color:#8899ff;background:rgba(100,100,255,.08);padding:2px 8px;border-radius:3px;border:1px solid rgba(100,100,255,.15)">${escapeHTML(meta.version)}</span>`
            : '';

        html += `
        <div style="background:#070707;border:1px solid #1e1e1e;border-radius:4px;padding:16px;margin-bottom:12px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
                <span style="font-family:var(--font-mono);font-size:13px;color:#f0f0f0;font-weight:700">${lang === 'es' ? 'Puerto' : 'Port'} ${escapeHTML(String(port))} — ${escapeHTML(meta.name || '?')}</span>
                ${verBadge}
                <span style="font-family:var(--font-mono);font-size:10px;color:#555;margin-left:auto">${lang === 'es' ? 'Búsqueda' : 'Search'}: &quot;${escapeHTML(keyword)}&quot; · ${r.total || 0} ${totalLbl}</span>
            </div>`;

        if (r.error) {
            html += `<div style="color:#ff8866;font-family:var(--font-mono);font-size:11px">⚠ ${escapeHTML(r.error)}</div></div>`;
            return;
        }
        if (!cves.length) {
            html += `<div style="color:#555;font-family:var(--font-mono);font-size:11px">${lang === 'es' ? 'Sin CVEs encontrados' : 'No CVEs found'}</div></div>`;
            return;
        }

        cves.forEach(cve => {
            const sc   = sevColor[cve.severity] || '#555';
            const sl   = lang === 'es' ? (sevLabel[cve.severity] || cve.severity) : cve.severity;
            const href = safeHref(cve.nvd_url);
            html += `
            <div style="background:#0a0a0a;border:1px solid #1a1a1a;border-left:3px solid ${sc};border-radius:3px;padding:12px 14px;margin-bottom:7px">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap">
                    <a href="${escapeHTML(href)}" target="_blank" rel="noopener noreferrer" style="font-family:var(--font-mono);font-size:12px;color:#8899ff;font-weight:700;text-decoration:none">${escapeHTML(cve.id)}</a>
                    ${cve.cvss_score !== null ? `<span style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:${sc}">CVSS ${cve.cvss_score} — ${escapeHTML(sl)}</span>` : ''}
                    <span style="font-family:var(--font-mono);font-size:10px;color:#555;margin-left:auto">${escapeHTML(cve.published)}</span>
                </div>
                <div style="font-size:12px;color:#bbb;line-height:1.6">${escapeHTML(cve.description)}</div>
            </div>`;
        });
        html += '</div>';
    });

    return { html, totalCVEs };
}

// ── CVE placeholder ───────────────────────────────────────────────────────────

export function tmplCVEPlaceholder(lang) {
    // ── CSP-compliant: data-action="launch-cve" replaces onclick ─────────────
    // Hover effect handled entirely by CSS class .btn-cve-launch
    // (injected once into <head> by initDelegationStyles() in ui.js)
    return `<div class="no-results" style="padding:36px 24px">[ 🐛 ]<br>
        <span style="display:block;margin:12px 0 20px;font-size:12px">${lang === 'es' ? 'Ejecuta <b style="color:#aaa">Fingerprinting</b> para resultados precisos, o lanza el análisis ahora.' : 'Run <b style="color:#aaa">Fingerprinting</b> for precise results, or launch analysis now.'}</span>
        <button id="btn-launch-cve"
                class="btn-cve-launch"
                data-action="launch-cve"
                style="padding:8px 22px;background:transparent;border:1px solid #333;border-radius:4px;color:#888;font-family:var(--font-mono);font-size:11px;cursor:pointer;letter-spacing:.8px;transition:border-color .2s,color .2s">
            🐛 ${lang === 'es' ? 'Buscar CVEs ahora' : 'Search CVEs now'}
        </button></div>`;
}

// ── CVE loading placeholder ────────────────────────────────────────────────────

export function tmplCVELoading(lang, openPortsCount) {
    const est = Math.ceil(openPortsCount * 6.5);
    return `<div class="audit-loading"><span class="spinner"></span><span class="es">Buscando CVEs conocidos... (puede tardar ~${est}s por límite de NVD)</span><span class="en">Searching CVEs... (~${est}s due to NVD rate limit)</span></div>`;
}

// ── Discover output ───────────────────────────────────────────────────────────

export function tmplDiscoverOutput(data, cidr, lang) {
    if (!data.alive?.length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron hosts activos' : 'No live hosts found'} en ${escapeHTML(cidr)}</div>`;
    }

    // ── CSP-compliant host cards: data-action="scan-host" data-host="{ip}" ───
    // No inline JS. Delegated listener in main.js handles click.
    const hostCards = data.alive.map(h => `
        <div class="discover-host-card"
             role="button"
             tabindex="0"
             data-action="scan-host"
             data-host="${escapeHTML(h.ip)}"
             style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:#0a0a0a;border:1px solid rgba(0,255,136,.15);border-radius:4px;cursor:pointer;transition:border-color .15s"
             title="${lang === 'es' ? 'Clic para escanear' : 'Click to scan'}">
            <span style="width:7px;height:7px;border-radius:50%;background:#00ff88;box-shadow:0 0 4px #00ff88;flex-shrink:0"></span>
            <span style="font-family:var(--font-mono);font-size:13px;color:#00cc66;font-weight:600">${escapeHTML(h.ip)}</span>
            ${h.rtt_ms !== null ? `<span style="font-family:var(--font-mono);font-size:10px;color:#555">${h.rtt_ms} ms</span>` : ''}
        </div>`).join('');

    return `<div class="audit-stat-bar" style="margin-bottom:14px">
        <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">${lang === 'es' ? 'Hosts activos' : 'Live hosts'}</span><span class="asb-num" style="color:#00ff88">${data.alive_count}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">${lang === 'es' ? 'Rango' : 'Range'}</span><span class="asb-num" style="color:#888">${data.total_hosts}</span></div>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:6px">${hostCards}</div>`;
}

// ── Subdomains output ─────────────────────────────────────────────────────────

export function tmplSubdomainsOutput(data, domain, lang) {
    if (!data.subdomains?.length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron subdominios' : 'No subdomains found'} para ${escapeHTML(domain)}</div>`;
    }

    // ── CSP-compliant scan buttons: data-action="scan-host" data-host="{sub}" ─
    const rows = data.subdomains.map(s => `
        <tr>
            <td class="col-service">${escapeHTML(s.subdomain)}</td>
            <td style="font-family:var(--font-mono);font-size:11px;color:${s.resolves ? '#00cc66' : '#555'}">${escapeHTML(s.ip || (s.resolves === false ? '✗ NXDOMAIN' : '—'))}</td>
            <td style="font-family:var(--font-mono);font-size:10px;color:#666">${escapeHTML(s.not_after || '—')}</td>
            <td><button class="btn-export"
                        style="padding:3px 9px;font-size:10px"
                        data-action="scan-host"
                        data-host="${escapeHTML(s.subdomain)}"
                >→ ${lang === 'es' ? 'Escanear' : 'Scan'}</button></td>
        </tr>`).join('');

    return `<div class="audit-stat-bar" style="margin-bottom:14px">
        <div class="asb-item"><div class="asb-dot" style="background:#8899ff"></div><span class="asb-label">${lang === 'es' ? 'Subdominios encontrados' : 'Subdomains found'}</span><span class="asb-num" style="color:#8899ff">${data.total}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">${lang === 'es' ? 'Resueltos' : 'Resolved'}</span><span class="asb-num" style="color:#00ff88">${data.subdomains.filter(s => s.resolves).length}</span></div>
    </div>
    <div class="table-wrap" style="max-height:320px">
        <table>
            <thead><tr>
                <th>${lang === 'es' ? 'Subdominio' : 'Subdomain'}</th>
                <th>IP</th>
                <th>${lang === 'es' ? 'Cert válido hasta' : 'Cert expiry'}</th>
                <th></th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>
    </div>`;
}

// ── HTML Report ───────────────────────────────────────────────────────────────
//
// Non-blocking API: export.js builds rowsHtml asynchronously (chunked) and
// passes it as prebuiltRowsHtml.  This function never touches results.map()
// when the pre-built string is present, keeping the main thread free.
//
// Fallback: when called without prebuiltRowsHtml (e.g. from tests), it falls
// back to a synchronous build — backwards compatible.

export function tmplHTMLReport(
    { meta, results, counts, auditData, geoData, versions, getRisk },
    prebuiltRowsHtml = null,
) {
    const ts  = new Date().toLocaleString();
    const rc  = { high: '#ff0033', medium: '#ffaa00', low: '#00ff88', info: '#444' };
    const rl2 = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: '—' };
    const geo = geoData || {};

    // ── Row HTML: use pre-built async version when available ──────────────────
    const rowsHtml = prebuiltRowsHtml ?? (results || []).map(r => {
        const sc  = r.state === 'open' ? '#00ff88' : r.state === 'filtered' ? '#ffaa00' : '#ff4444';
        const rk  = getRisk(r.port);
        const ver = versions[r.port]?.version || '';
        return `<tr><td>${r.port}</td><td style="color:${sc}">● ${escapeHTML(r.state.charAt(0).toUpperCase() + r.state.slice(1))}</td><td>${escapeHTML(r.service)}</td><td style="color:${rc[rk]};font-size:10px">${rl2[rk]}</td><td>${r.response_time_ms ?? '—'} ms</td><td style="font-size:10px;color:#666;max-width:160px;overflow:hidden">${escapeHTML(ver)}</td></tr>`;
    }).join('');

    const geoHtml = geo.country
        ? `<tr><td style="color:#444;width:160px">Location</td><td>${escapeHTML(geo.city || '')} · ${escapeHTML(geo.country || '')} · ${escapeHTML(geo.asn || '')}</td></tr><tr><td style="color:#444">ISP</td><td>${escapeHTML(geo.isp || '—')}</td></tr>`
        : '';

    let auditHtml = '';
    if (auditData) {
        const hd = auditData.headers;
        if (hd && !hd.error) {
            const gc2 = GRADE_COLOR[hd.grade] || '#888';
            auditHtml += `<h2>HTTP Security Headers — Grade: <span style="color:${gc2}">${escapeHTML(hd.grade)}</span> (${hd.score}/100)</h2>${hd.missing?.length ? '<p style="color:#ff0033;margin-bottom:6px">Missing: ' + hd.missing.map(h => `<code>${escapeHTML(h.header)}</code>`).join(', ') + '</p>' : ''}`;
        }
        const td = auditData.technologies;
        if (td?.technologies?.length) {
            auditHtml += `<h2>Detected Technologies (${td.count})</h2><p>${td.technologies.map(t => `${escapeHTML(t.icon)} ${escapeHTML(t.name)}`).join(' · ')}</p>`;
        }
        const pd = auditData.paths;
        if (pd?.found?.length) {
            auditHtml += `<h2>Sensitive Paths (${pd.total_found} found)</h2><table><thead><tr><th>Path</th><th>Status</th><th>Severity</th></tr></thead><tbody>${pd.found.map(f => `<tr><td>${escapeHTML(f.path)}</td><td>${f.status_code}</td><td style="color:${rc[safeSev(f.severity)] || '#888'}">${escapeHTML(f.severity.toUpperCase())}</td></tr>`).join('')}</tbody></table>`;
        }
    }

    const totalCount = prebuiltRowsHtml !== null ? (counts.open + counts.closed + counts.filtered) : (results?.length ?? 0);

    return `<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>LukitaPort Report</title><link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;700&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#050505;color:#f0f0f0;font-family:'Inter',sans-serif;font-size:13px;padding:40px;line-height:1.6}h1{font-size:1.8rem;color:#ff0033;margin-bottom:4px;font-family:'IBM Plex Mono',monospace}.sub{color:#555;font-size:11px;letter-spacing:1.5px;margin-bottom:32px;font-family:'IBM Plex Mono',monospace}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:#1a1a1a;margin-bottom:28px;border-radius:4px;overflow:hidden}.card{background:#0d0d0d;padding:20px;text-align:center}.card .n{font-size:2.2rem;font-weight:700;line-height:1;margin-bottom:5px;font-family:'IBM Plex Mono',monospace}.card .l{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#333}h2{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#444;margin:28px 0 12px;border-bottom:1px solid #111;padding-bottom:8px;font-family:'IBM Plex Mono',monospace}table{width:100%;border-collapse:collapse}th{text-align:left;padding:9px 14px;font-size:10px;letter-spacing:1.2px;text-transform:uppercase;color:#333;border-bottom:1px solid #111;font-weight:600;font-family:'IBM Plex Mono',monospace}td{padding:10px 14px;border-bottom:1px solid rgba(20,20,20,.9);font-family:'IBM Plex Mono',monospace;font-size:12px}code{background:#111;padding:1px 6px;border-radius:2px;color:#ffaa00;font-family:'IBM Plex Mono',monospace}p{color:#888;font-size:12px;margin-bottom:12px}footer{margin-top:40px;color:#333;font-size:11px;text-align:center;border-top:1px solid #111;padding-top:18px;font-family:'IBM Plex Mono',monospace}</style></head><body><h1>LukitaPort</h1><div class="sub">PORT SCAN REPORT · ${ts}</div><div class="grid"><div class="card"><div class="n" style="color:#00ff88">${counts.open}</div><div class="l">Open</div></div><div class="card"><div class="n" style="color:#ff4444">${counts.closed}</div><div class="l">Closed</div></div><div class="card"><div class="n" style="color:#ffaa00">${counts.filtered}</div><div class="l">Filtered</div></div><div class="card"><div class="n" style="color:#ff0033">${totalCount}</div><div class="l">Total</div></div></div><h2>Scan Metadata</h2><table><tr><td style="color:#444;width:160px">Target</td><td>${escapeHTML(meta.input ?? '—')}</td></tr><tr><td style="color:#444">Resolved IP</td><td>${escapeHTML(meta.ip ?? '—')}</td></tr><tr><td style="color:#444">Hostname</td><td>${escapeHTML(meta.hostname ?? '—')}</td></tr><tr><td style="color:#444">Mode</td><td>${escapeHTML(meta.mode ?? '—')}</td></tr><tr><td style="color:#444">Profile</td><td>${escapeHTML(meta.profile ?? 'normal')}</td></tr>${geoHtml}<tr><td style="color:#444">Generated</td><td>${ts}</td></tr></table><h2>All Results</h2><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Risk</th><th>Response</th><th>Version</th></tr></thead><tbody>${rowsHtml}</tbody></table>${auditHtml}<footer>LukitaPort · jaimefg1888 · For educational use only</footer></body></html>`;
}
