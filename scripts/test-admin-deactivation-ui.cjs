// Targeted UI syntax, typed-MAC guard and request/refresh behavior. No browser mutation.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../internal/httpapi/web/index.html'), 'utf8');
for (const script of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) new vm.Script(script[1]);
assert.ok(html.includes('/assets/deactivation.js'));
const script = fs.readFileSync(path.join(__dirname, '../internal/httpapi/web/deactivation.js'), 'utf8');
new vm.Script(script);
function element(tag) { return {tag, children:[], handlers:{}, style:{}, value:'', isConnected:true,
  append(...items){this.children.push(...items)}, addEventListener(event, action){this.handlers[event]=action}}; }
async function check(refreshFails) {
  const nodes=[], requests=[], notices=[], body=element('body');
  const device={id:'original-id', serial:'020000009201', mac:'02:00:00:00:92:01', config_version:7};
  let closed=false;
  const context={state:{selectedDevice:device}, openDrawer(){},
    document:{getElementById(){return body}, createElement(tag){const node=element(tag);nodes.push(node);return node}},
    confirm(){return true}, closeDrawer(){closed=true}, toast(...args){notices.push(args)},
    async api(endpoint, options){requests.push([endpoint, JSON.parse(options.body)]);return {message:'revoked'}},
    async loadState(){if(refreshFails) throw Error('network unavailable')}};
  vm.runInNewContext(script, context);
  context.openDrawer(device.id);
  const input=nodes.find(n=>n.tag==='input'), button=nodes.find(n=>n.tag==='button');
  assert.equal(button.className, 'btn secondary small'); assert.equal(button.disabled, true);
  input.value='02:00:00:00:92:02'; input.handlers.input(); assert.equal(button.disabled, true);
  await button.handlers.click(); assert.equal(requests.length, 0);
  input.value='02:00:00:00:92:01'; input.handlers.input(); assert.equal(button.disabled, false);
  await button.handlers.click(); assert.equal(closed,true); assert.equal(requests.length,1);
  assert.equal(requests[0][0],'/admin/devices/deactivate');
  assert.deepEqual(requests[0][1],{device_id:'original-id', expected_version:7, mac:input.value, confirm:'DEACTIVATE_DEVICE'});
  assert.equal(notices[0][0],'设备已反激活');
  if(refreshFails) assert.equal(notices[1][0],'反激活已完成，列表刷新失败');
}
check(false).then(()=>check(true)).then(()=>console.log('Admin deactivation UI, typed MAC guard and confirmation flow: OK')).catch(error=>{console.error(error);process.exitCode=1});
