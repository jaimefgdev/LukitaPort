// state.js
// Single source of truth — imported by all other modules.

export const state = {
    results:     [],
    scanMeta:    null,
    scanning:    false,
    filter:      'all',
    counts:      { open: 0, closed: 0, filtered: 0 },
    eventSource: null,
    lang:        'es',
    auditData:   null,
    versions:    {},
    geoData:     null,
    portRisk:    {},   // Populated at startup from /api/config
};

export const RISK_LABELS = {
    es: { high: 'Alto riesgo', medium: 'Riesgo medio', low: 'Bajo riesgo', info: '—' },
    en: { high: 'High risk',   medium: 'Medium risk',  low: 'Low risk',    info: '—' },
};

export const getRisk = p => state.portRisk[p] || state.portRisk[String(p)] || 'info';

export async function initConfig() {
    try {
        const resp = await fetch('/api/config');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        // Keys come as strings from JSON; keep them as-is so getRisk works with both
        state.portRisk = data.portRisk || {};
    } catch (e) {
        console.warn('[LukitaPort] Failed to load remote config, PORT_RISK will be empty:', e);
    }
}
