'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const html = fs.readFileSync(path.join(__dirname, '../internal/localadmin/web/index.html'), 'utf8');
const start = html.indexOf('  function latencyPresentation(');
const end = html.indexOf('  async function api(', start);
assert.ok(start >= 0 && end > start, 'real UI presentation functions must exist');
const context = vm.createContext({document: {createElement(tag) {
  return {tag, children: [], textContent: '', append(...children) {this.children.push(...children);}};
}}});
vm.runInContext(html.slice(start, end) + '\nglobalThis.present=latencyPresentation;globalThis.make=nodeLatencyElement;', context);
const now = Date.parse('2026-10-02T01:10:00Z');
const result = (ms, age=0) => ({status:'ok', latency_ms:ms, checked_at:new Date(now-age).toISOString()});

test('manual probe explains warm-up without changing latency colors or controls', () => {
  assert.match(html, /先通过 dae 的真实 HTTP 检查预热，再记录后续测量/);
  assert.match(html, /正在预热并测速/);
  assert.match(html, /没有正式新结果时保留上次真实结果/);
});

test('actual UI uses green/yellow/red at the existing boundaries', () => {
  for (const [ms,color] of [[0,'good'],[149,'good'],[150,'warn'],[300,'warn'],[301,'bad']]) {
    const view=context.present(result(ms),now);
    assert.equal(view.text,ms===0?'<1 ms':ms+' ms');
    assert.equal(view.color,color);
    assert.equal(view.stale,false);
  }
});
test('older result retains latency color and original timestamp without looking current', () => {
  const view=context.present(result(122,300001),now);
  assert.equal(view.text,'122 ms');
  assert.equal(view.color,'good');
  assert.equal(view.stale,true);
  assert.equal(view.checkedAt,now-300001);
});
test('failed results stay distinct from unmeasured and stale failures', () => {
  const fresh={status:'failed',checked_at:new Date(now).toISOString()};
  assert.equal(context.present(fresh,now).text,'连接失败');
  assert.equal(context.present(fresh,now).color,'bad');
  const stale={...fresh,checked_at:new Date(now-600000).toISOString()};
  assert.equal(context.present(stale,now).text,'连接失败');
  assert.equal(context.present(stale,now).color,'bad');
});
test('missing, invalid, or future observations never turn into zero latency', () => {
  for (const value of [null,{status:'unknown'},result(-1),{...result(42),latency_ms:null}]) {
    assert.equal(context.present(value,now).text,'未测速');
    assert.equal(context.present(value,now).color,'unknown');
  }
  for (const value of [{...result(42),checked_at:'invalid'},result(42,-60001)]) {
    assert.equal(context.present(value,now).text,'时间异常');
    assert.equal(context.present(value,now).color,'unknown');
  }
});
test('real node element visibly renders value, color, and update time', () => {
  const row=context.make(result(304),'http://cp.cloudflare.com',now);
  assert.equal(row.children[0].textContent,'304 ms');
  assert.equal(row.children[0].className,'node-latency latency-bad');
  assert.match(row.children[1].textContent,/^更新 \d{2}:\d{2}$/);
  assert.match(row.title,/HTTP 延迟/);
});
test('older node element keeps color and visibly marks its original update time', () => {
  const row=context.make(result(122,600000),'http://cp.cloudflare.com',now);
  assert.equal(row.children[0].textContent,'122 ms');
  assert.equal(row.children[0].className,'node-latency latency-good');
  assert.match(row.children[1].textContent,/^上次 · \d{2}:\d{2}$/);
  assert.match(row.title,/保留上次真实结果，不代表当前延迟/);
});
