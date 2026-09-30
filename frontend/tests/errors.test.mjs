import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeError, errorInfoFromBody, errorInfoFromSSE, codeForStatus } from '../errors.js';

test('SSRF block from the scan stream is explained', () => {
    const info = errorInfoFromSSE({ error: 'Scanning internal addresses is not permitted (resolved: 127.0.0.1).', status: 403 });
    assert.equal(info.code, 'ssrf_blocked');
    assert.match(describeError(info, 'es'), /Destino bloqueado.*ALLOW_PRIVATE_IPS/);
    assert.match(describeError(info, 'en'), /Target blocked/);
});

test('401 asks to sign in again', () => {
    assert.match(describeError(errorInfoFromBody(401, { ok: false, error: 'unauthorized', detail: 'x' }), 'es'), /token/);
    assert.equal(codeForStatus(401), 'unauthorized');
});

test('validation and resolution errors keep the server detail', () => {
    const v = errorInfoFromBody(422, { ok: false, error: 'validation_error', detail: 'target: not a host' });
    assert.equal(describeError(v, 'es'), 'Datos no válidos: target: not a host');
    const u = errorInfoFromBody(400, { ok: false, error: 'unresolvable', detail: 'Could not resolve target: nx' });
    assert.match(describeError(u, 'en'), /^Could not resolve the target: /);
});

test('scan stream errors without a known code show the server text', () => {
    const info = errorInfoFromSSE({ error: 'Invalid custom range: 200 > 100', status: 422 });
    assert.equal(describeError(info, 'es'), 'Invalid custom range: 200 > 100');
    const res = errorInfoFromSSE({ error: 'Local resources exhausted (EMFILE)', status: 503 });
    assert.equal(describeError(res, 'es'), 'Local resources exhausted (EMFILE)');
});

test('busy, rate limit, network and unknown statuses', () => {
    assert.match(describeError(errorInfoFromBody(429, { error: 'busy' }), 'es'), /máximo de operaciones/);
    assert.match(describeError(errorInfoFromBody(429, { error: 'rate_limited' }), 'es'), /Demasiadas peticiones/);
    assert.match(describeError({ status: 0, code: 'network' }, 'es'), /No se pudo contactar/);
    assert.equal(describeError(errorInfoFromBody(418, null), 'en'), 'Server error (HTTP 418).');
    assert.equal(describeError(errorInfoFromBody(404, { error: 'not_found', detail: 'Not Found' }), 'en'), 'Not Found');
});

test('non-JSON error bodies fall back to the status', () => {
    const info = errorInfoFromBody(502, null);
    assert.equal(info.code, 'upstream_error');
    assert.equal(describeError(info, 'es'), 'Servicio externo no disponible');
});
