// Isolated local UI regression; never contacts a real OEC or cloud.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const html = fs.readFileSync(path.join(__dirname, '../internal/localadmin/web/index.html'), 'utf8');
  const backup = {
    format: 'ty-gateway-customer-config-v1', device_code: 'AABBCCDDEE01',
    exported_at: '2026-09-27T00:00:00Z', rules: [{match_type:'domain_suffix',match_value:'example.org',action:'DIRECT'}],
    preferences: {}, proxy_enabled_at_export: false,
  };
  const writes = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    if (req.method === 'POST' && req.url.startsWith('/api/config/')) writes.push({path:req.url,body:JSON.parse(body)});
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/status') return res.end(JSON.stringify({setup_required:false,recovery_enabled:false,device_code:'AABBCCDDEE01'}));
    if (req.url === '/api/session') return res.end(JSON.stringify({device_code:'AABBCCDDEE01',interface:'eth0',addresses:['192.168.0.10/24'],network_controls:'draft_only'}));
    if (req.url === '/api/network/settings') return res.end(JSON.stringify({settings:{plan:{address_cidr:'192.168.0.10/24',gateway:'192.168.0.1',dhcp_enabled:false,dns_mode:'router'},dns_enabled:false,reservations:[]}}));
    if (req.url === '/api/network/services') return res.end(JSON.stringify({dhcp_active:false,lan_dns_active:false}));
    if (req.url === '/api/customer/me') return res.end(JSON.stringify({device:{serial:'AABBCCDDEE01',profile:'managed_geo',config_version:3},rules:[],nodes:[],categories:[],preferences:{}}));
    if (req.url === '/api/proxy') return res.end(JSON.stringify({enabled:false,applied:false,ready:true,daemon_active:false,node_count:0}));
    if (req.url === '/api/software/status') return res.end(JSON.stringify({version:'0.7.3',channel:'pilot',updating:false}));
    if (req.url === '/api/config/export') return res.end(JSON.stringify(backup));
    if (req.url === '/api/config/preview') return res.end(JSON.stringify({device_code:'AABBCCDDEE01',rules:1,preferences:0,network_draft:'保持当前网络预设',network_will_apply:false,proxy_will_enable:false,notice:'不会切换当前网络。'}));
    if (req.url === '/api/config/import') return res.end(JSON.stringify({ok:true,network_applied:false,message:'用户规则已恢复。'}));
    if (req.url === '/api/config/reset') return res.end(JSON.stringify({ok:true,proxy_enabled:false,message:'用户设置已重置。'}));
    res.setHeader('Content-Type', 'text/html; charset=utf-8');res.end(html);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({headless:true,executablePath:process.env.TY_UI_BROWSER || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'});
    const page = await browser.newPage({acceptDownloads:true});
    page.on('dialog', dialog => dialog.type() === 'prompt' ? dialog.accept('重置') : dialog.accept());
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.getByRole('button',{name:'更新与备份'}).click();
    assert.equal(await page.getByText('配置备份与恢复').isVisible(),true);
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button',{name:'下载本机配置'}).click();
    const download = await downloadPromise;
    assert.match(download.suggestedFilename(), /AABBCCDDEE01-config\.json$/);
    await page.locator('#config-file').setInputFiles({name:'config.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(backup))});
    assert.equal(await page.locator('#config-import').isDisabled(),true);
    await page.getByRole('button',{name:'检查并预览'}).click();
    await page.getByText(/用户规则 1 条/).waitFor();
    assert.equal(await page.locator('#config-import').isEnabled(),true);
    const imported = page.waitForResponse(response => response.url().endsWith('/api/config/import'));
    await page.getByRole('button',{name:'确认导入'}).click();
    await imported;
    assert.equal(writes.find(entry=>entry.path==='/api/config/import')?.body.device_code,backup.device_code);
    await page.waitForTimeout(2000);
    await page.getByRole('button',{name:'更新与备份'}).click();
    const reset = page.waitForResponse(response => response.url().endsWith('/api/config/reset'));
    await page.getByRole('button',{name:'重置用户设置'}).click();
    await reset;
    assert.equal(writes.find(entry=>entry.path==='/api/config/reset')?.body.confirm,'RESET_CUSTOMER_SETTINGS');
    console.log('PASS: backup download, preview gate, confirmed import and customer-only reset');
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {console.error(error);process.exitCode=1});
