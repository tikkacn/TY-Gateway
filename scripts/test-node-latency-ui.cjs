// Targeted, dependency-free UI syntax and latency presentation checks.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, '../internal/localadmin/web/index.html'), 'utf8');
for (const match of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]);
const start = html.indexOf('  function latencyPresentation(');
const end = html.indexOf('  const categoryLabels=', start);
assert.ok(start > 0 && end > start, 'latency presenter missing');
const present = vm.runInNewContext(html.slice(start, end) + ';latencyPresentation');
const now = Date.now(), stamp = new Date(now).toISOString();
for (const [status, ms, color, text] of [
  ['ok', 49, 'good', '49 ms'], ['ok', 0, 'good', '<1 ms'],
  ['ok', 150, 'warn', '150 ms'], ['ok', 300, 'warn', '300 ms'], ['ok', 301, 'bad', '301 ms'],
  ['failed', undefined, 'bad', '连接失败'], ['unknown', undefined, 'unknown', '未测速'],
  ['ok', null, 'unknown', '未测速'], ['ok', -1, 'unknown', '未测速'],
]) {
  const view = present({status, latency_ms: ms, checked_at: stamp}, now);
  assert.equal(view.color, color); assert.equal(view.text, text);
}
assert.equal(present(undefined, now).text, '未测速');
assert.equal(present({status:'ok', latency_ms:49, checked_at:new Date(now - 300001).toISOString()}, now).color, 'good');
assert.equal(present({status:'ok', latency_ms:49, checked_at:new Date(now - 300001).toISOString()}, now).stale, true);
assert.equal(present({status:'ok', latency_ms:49, checked_at:new Date(now + 60001).toISOString()}, now).color, 'unknown');
for (const route of ['/speed-test', '/speed-test/settings', '/speed-test/run']) assert.ok(html.includes(route));
for (const color of ['good','warn','bad','unknown']) assert.ok(html.includes('.latency-'+color));
console.log('Node latency UI syntax, colors, unknown/stale handling and controls: OK');
