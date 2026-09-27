// Mocked administrator UI regression; it never contacts a real control plane.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const html = fs.readFileSync(path.join(__dirname, '../internal/httpapi/web/index.html'), 'utf8');
  const device = {id:'0123456789abcdef0123456789abcdef',device_number:2,serial:'AABBCCDDEE01',name:'测试设备',state:'enabled',online:true,profile:'managed_geo',config_version:5,rescue_ssh_port:22001};
  let resetBody=null, resetCookie='';
  const server=http.createServer(async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk;
    res.setHeader('Content-Type','application/json');
    if(req.url==='/api/v1/admin/session')return res.end(JSON.stringify({authenticated:false}));
    if(req.url==='/api/v1/admin/login'){res.setHeader('Set-Cookie','test_admin_session=fixture; HttpOnly; SameSite=Strict; Path=/');return res.end(JSON.stringify({ok:true}))}
    if(req.url==='/assets/enrollments.js'){res.setHeader('Content-Type','application/javascript');return res.end('')}
    if(req.url==='/api/v1/admin/devices/reset-customer-settings'){
      resetBody=JSON.parse(body);resetCookie=req.headers.cookie||'';device.config_version++;
      return res.end(JSON.stringify({ok:true,reload_queued:true,config_version:device.config_version}));
    }
    if(req.url==='/api/v1/admin/devices')return res.end(JSON.stringify({devices:[device]}));
    if(req.url==='/api/v1/admin/subscriptions')return res.end(JSON.stringify({subscriptions:[]}));
    if(req.url==='/api/v1/admin/rules')return res.end(JSON.stringify({rules:[{id:'baseline',source:'admin',source_type:'admin',match_type:'domain_suffix',match_value:'example.org',action:'PROXY',priority:100}]}));
    if(req.url==='/api/v1/admin/provider-catalog')return res.end(JSON.stringify({categories:[],profiles:[]}));
    if(req.url==='/api/v1/admin/rule-packages')return res.end(JSON.stringify({packages:[]}));
    if(req.url?.startsWith('/api/v1/'))return res.end('{}');
    res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.TY_UI_BROWSER||'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'});
    const page=await browser.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
    page.on('dialog',dialog=>dialog.accept());
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.locator('#tokenInput').fill('admin');await page.locator('#loginBtn').click();
    await page.locator('[data-page="devices"]').first().click();
    await page.getByRole('button',{name:'查看详情'}).click();
    await page.getByRole('heading',{name:'客户求助 · 回到基础规则'}).waitFor();
    const reset=page.waitForResponse(response=>response.url().endsWith('/admin/devices/reset-customer-settings'));
    await page.getByRole('button',{name:'重置客户分流到基础状态'}).click();await reset;
    assert.equal(resetBody.device_id,device.id);assert.equal(resetBody.expected_version,5);
    assert.equal(resetBody.confirm,'RESET_CUSTOMER_SETTINGS');assert.match(resetCookie,/test_admin_session=fixture/);
    assert.deepEqual(errors,[]);
    console.log('PASS: administrator support reset is explicit, scoped and authenticated in UI');
  }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(error=>{console.error(error);process.exitCode=1});
