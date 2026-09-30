// Run with: node --test frontend/tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cleanTarget, csvField, validatePortRange } from '../utils.js';

test('cleanTarget handles hosts, URLs and ports', () => {
    assert.equal(cleanTarget('  example.com  '), 'example.com');
    assert.equal(cleanTarget('https://example.com/path?q=1#x'), 'example.com');
    assert.equal(cleanTarget('example.com:8080'), 'example.com');
    assert.equal(cleanTarget('192.168.1.1:22'), '192.168.1.1');
    assert.equal(cleanTarget('http://user:pw@example.com:81/'), 'example.com');
});

test('cleanTarget keeps IPv6 literals intact', () => {
    assert.equal(cleanTarget('::1'), '::1');
    assert.equal(cleanTarget('2001:db8::1'), '2001:db8::1');
    assert.equal(cleanTarget('[2001:db8::1]'), '2001:db8::1');
    assert.equal(cleanTarget('[2001:db8::1]:443'), '2001:db8::1');
    assert.equal(cleanTarget('http://[::1]:8080/admin'), '::1');
});

test('csvField quotes and neutralises formulas', () => {
    assert.equal(csvField('nginx'), '"nginx"');
    assert.equal(csvField('a "b"'), '"a ""b"""');
    assert.equal(csvField('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
    assert.equal(csvField('+1'), '"\'+1"');
    assert.equal(csvField('-1'), '"\'-1"');
    assert.equal(csvField('@SUM(A1)'), '"\'@SUM(A1)"');
    assert.equal(csvField(null), '""');
});

test('validatePortRange', () => {
    assert.equal(validatePortRange(1, 1024), null);
    assert.equal(validatePortRange(80, 80), null);
    assert.equal(validatePortRange(200, 100), 'inverted');
    assert.equal(validatePortRange(0, 10), 'out_of_range');
    assert.equal(validatePortRange(1, 70000), 'out_of_range');
    assert.equal(validatePortRange('a', 10), 'not_integer');
});
