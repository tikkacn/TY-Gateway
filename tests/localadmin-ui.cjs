// Isolated browser regression: no real device or user credentials are used.
// Requires Playwright and a Chromium executable (TY_UI_BROWSER or installed Chrome).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const html = fs.readFileSync(path.join(__dirname, '../internal/localadmin/web/index.html'), 'utf8');
  let saved = {plan:{address_cidr:'192.168.0.10/24',gateway:'192.168.0.1',dhcp_enabled:true,pool_start:'192.168.0.100',pool_end:'192.168.0.200',dns_mode:'router'},dns_enabled:true,reservations:[]};
  let writes = 0, rejectSave = false, rejectRead = false;
  const server = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    let input = ''; for await (const part of req) input += part;
    const state = {device_code:'TESTDEVICE',interface:'eth0',addresses:['192.168.0.211/24'],default_gateway:'192.168.0.1',network_controls:'draft_only'};
    if (req.url === '/api/status') return res.end(JSON.stringify({setup_required:false,recovery_enabled:false}));
    if (req.url === '/api/session') return res.end(JSON.stringify(state));
    if (req.url === '/api/network/settings' && req.method === 'GET') {
      if (rejectRead) {res.statusCode = 500; return res.end(JSON.stringify({error:'read fixture failure'}));}
      return res.end(JSON.stringify({settings:saved}));
    }
    if (req.url === '/api/network/preview') {
      const plan = JSON.parse(input);
      return res.end(JSON.stringify({...plan,client_gateway:plan.address_cidr.split('/')[0]}));
    }
    if (req.url === '/api/network/settings' && req.method === 'PUT') {
      if (rejectSave) {res.statusCode=500; return res.end(JSON.stringify({error:'无法保存，请重试（测试）'}));}
      saved = {...JSON.parse(input),updated_at:new Date().toISOString()}; writes++;
      return res.end(JSON.stringify({settings:saved,notice:'此为预设，尚未应用。',applied:false}));
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(html);
  });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  let browser;
  try {
    browser = await chromium.launch({headless:true,executablePath:process.env.TY_UI_BROWSER || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'});
    const page = await browser.newPage({viewport:{width:1100,height:850}});
    await page.addInitScript(() => {
      window.domFailures=[];
      const original=Node.prototype.insertBefore;
      Node.prototype.insertBefore=function(...args){try{return original.apply(this,args)}catch(e){window.domFailures.push(e.name+': '+e.message);throw e}};
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.waitForFunction(() => document.querySelector('#planAddress'));
    assert.equal(await page.locator('#appView').isVisible(),true,JSON.stringify(await page.evaluate(() => window.domFailures)));
    await page.waitForFunction(() => document.querySelector('#planGateway').value==='192.168.0.1');
    const button = page.getByRole('button',{name:'检查并保存预设',exact:true});
    const result = page.locator('#planAddress').locator('xpath=ancestor::form').locator('[role=status]');
    assert.equal(await result.count(),1,'The feedback must be attached to the form.');
    await page.locator('#routerDhcpOff').check();
    await button.click();
    await result.filter({hasText:'预设已保存'}).waitFor({state:'visible'});
    assert.equal(writes,1);
    assert.equal(saved.plan.address_cidr,'192.168.0.10/24');
    assert.equal(await button.isEnabled(),true);
    await page.locator('#planGateway').fill('192.168.0.10');
    await button.click();
    await result.filter({hasText:'不能与 OEC'}).waitFor({state:'visible'});
    assert.equal(writes,1,'Invalid input must not be sent for saving.');
    await page.locator('#planGateway').fill('192.168.0.1');
    rejectSave=true;
    await button.click();
    await result.filter({hasText:'无法保存，请重试'}).waitFor({state:'visible'});
    assert.equal(await button.isEnabled(),true);
    rejectSave=false;
    await page.reload();
    await page.getByText('上次保存：',{exact:false}).waitFor();
    assert.equal(await page.locator('#planAddress').inputValue(),'192.168.0.10/24');
    assert.equal(await page.getByRole('button',{name:'检查并保存预设',exact:true}).count(),1);
    rejectRead=true;
    await page.reload();
    await page.getByRole('status').filter({hasText:'本机预设读取失败'}).waitFor({state:'visible'});
    assert.deepEqual(await page.evaluate(() => window.domFailures),[]);
    console.log('PASS: initialization, visible save success, validation error, API error, saved reload, read error');
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(e => {console.error(e);process.exitCode=1});
