// Small, isolated checks: no real browser, device or network.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync(require('node:path').join(__dirname,'../internal/localadmin/web/index.html'),'utf8');
for(const script of html.matchAll(/<script>([\s\S]*?)<\/script>/g))new vm.Script(script[1]);
const start=html.indexOf('function describePackage(){'),end=html.indexOf("packageSelect.addEventListener('change'",start);
const context={state:{initialization_pending:true,device:{id:'device-1',profile:'managed_meta'},rule_packages:[{id:'managed_meta',name:'MetaCubeX',available:true,origin:'bundled',version:'a'.repeat(64),published_at:'2026-10-03T00:00:00Z'}]},packageSelect:{value:'managed_meta'},packageUse:{},packageStatus:{}};
vm.runInNewContext(html.slice(start,end)+';describePackage()',context);
assert.equal(context.packageUse.disabled,false);
assert.match(context.packageStatus.textContent,/安装包预置版本/);
assert.match(context.packageStatus.textContent,/不代表代理已准备好/);
assert.match(html,/state\.initialization_pending\).*unavailable\('首次初始化尚未完成/);
assert.match(html,/setTimeout\(refresh,5000\)/);
console.log('Early local rule menu: visible before nodes, truthful pending state and bounded polling OK');
