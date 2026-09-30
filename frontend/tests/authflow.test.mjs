import { test } from 'node:test';
import assert from 'node:assert/strict';
import { authenticate, tokenFromHash } from '../authflow.js';

function deps(overrides = {}) {
    const calls = [];
    const d = {
        hash: '',
        clearHash: () => calls.push('clearHash'),
        login: async t => { calls.push(`login:${t}`); return true; },
        logout: async () => { calls.push('logout'); },
        isAuthenticated: async () => { calls.push('status'); return true; },
        prompt: async r => { calls.push(`prompt:${r}`); },
        ...overrides,
    };
    return { d, calls };
}

test('tokenFromHash', () => {
    assert.equal(tokenFromHash('#token=abc'), 'abc');
    assert.equal(tokenFromHash('token=abc'), 'abc');
    assert.equal(tokenFromHash('#x=1&token=a-b_c'), 'a-b_c');
    assert.equal(tokenFromHash(''), null);
    assert.equal(tokenFromHash('#token='), null);
    assert.equal(tokenFromHash(undefined), null);
});

test('fragment token replaces an existing valid session', async () => {
    const { d, calls } = deps({ hash: '#token=NEW' });
    assert.equal(await authenticate(d), 'fragment');
    // It logs in with the new token and never asks whether the old session
    // is still valid.
    assert.deepEqual(calls, ['clearHash', 'login:NEW']);
});

test('rejected fragment token drops the old session and prompts', async () => {
    const { d, calls } = deps({ hash: '#token=OLD', login: async t => { calls.push(`login:${t}`); return false; } });
    assert.equal(await authenticate(d), 'prompt');
    assert.deepEqual(calls, ['clearHash', 'login:OLD', 'logout', 'prompt:invalid_fragment']);
});

test('network error on fragment login is treated as rejection', async () => {
    const { d, calls } = deps({ hash: '#token=X', login: async () => { throw new Error('down'); } });
    assert.equal(await authenticate(d), 'prompt');
    assert.ok(calls.includes('logout') && calls.includes('prompt:invalid_fragment'));
});

test('no fragment: existing session is kept', async () => {
    const { d, calls } = deps();
    assert.equal(await authenticate(d), 'session');
    assert.deepEqual(calls, ['status']);
});

test('no fragment and no session: prompt', async () => {
    const { d, calls } = deps({ isAuthenticated: async () => false });
    assert.equal(await authenticate(d), 'prompt');
    assert.deepEqual(calls, ['prompt:null']);
});
