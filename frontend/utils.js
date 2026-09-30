// utils.js
// Pure helpers with no DOM access, so they can be unit-tested with
// `node --test frontend/tests/`.

/**
 * cleanTarget — normalise what the user typed into a bare host.
 *
 * Accepts URLs, host:port and IPv6 in all common spellings:
 *   "https://example.com/path?q" → "example.com"
 *   "example.com:8080"           → "example.com"
 *   "192.168.1.1:22"             → "192.168.1.1"
 *   "[2001:db8::1]:443"          → "2001:db8::1"
 *   "http://[::1]:8080/"         → "::1"
 *   "2001:db8::1"                → "2001:db8::1"   (bare IPv6 keeps all colons)
 */
export function cleanTarget(raw) {
    let t = String(raw ?? '').trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    t = t.split(/[/?#]/)[0];
    t = t.replace(/^[^@]*@/, '');                     // drop user:pass@
    if (t.startsWith('[')) {                          // [v6] or [v6]:port
        const end = t.indexOf(']');
        return end > 0 ? t.slice(1, end) : t.slice(1);
    }
    const colons = (t.match(/:/g) || []).length;
    if (colons === 1) t = t.split(':')[0];            // host:port
    // colons >= 2 → bare IPv6 literal, keep as is
    return t.trim();
}

/**
 * csvField — quote a text value for CSV and neutralise spreadsheet formulas.
 *
 * Banners/versions come from the scanned host, so a value such as
 * `=HYPERLINK(...)` must not be evaluated when the CSV is opened in a
 * spreadsheet: values starting with = + - @ TAB or CR get a leading quote.
 */
export function csvField(value) {
    let v = String(value ?? '');
    if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
    return '"' + v.replace(/"/g, '""') + '"';
}

/**
 * validatePortRange — returns an error key or null for the custom range.
 */
export function validatePortRange(start, end) {
    const s = Number(start), e = Number(end);
    if (!Number.isInteger(s) || !Number.isInteger(e)) return 'not_integer';
    if (s < 1 || e > 65535 || e < 1 || s > 65535) return 'out_of_range';
    if (s > e) return 'inverted';
    return null;
}
