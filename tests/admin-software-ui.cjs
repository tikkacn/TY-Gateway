// Administrator maintenance UI regression; all API responses are mocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const html = fs.readFileSync(path.join(__dirname, '../internal/httpapi/web/index.html'), 'utf8');
  const device = {id:'0123456789abcdef0123456789abcdef',device_number:2,serial:'AABBCCDDEE01',name:'测试设备',state:'enabled',online:true,profile:'managed_geo',config_version:5};
  const maintenance=[];
  let remoteSupported=true;
  const server=http.createServer(async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk;
    res.setHeader('Content-Type','application/json');
    if(req.url==='/api/v1/admin/session')return res.end(JSON.stringify({authenticated:false}));
    if(req.url==='/api/v1/admin/login'){res.setHeader('Set-Cookie','test_admin_session=fixture; HttpOnly; SameSite=Strict; Path=/');return res.end(JSON.stringify({ok:true}))}
    if(req.url==='/assets/enrollments.js'){res.setHeader('Content-Type','application/javascript');return res.end('')}
    if(req.url?.startsWith('/api/v1/admin/devices/software?'))return res.end(JSON.stringify({remote_supported:remoteSupported,reported_agent_version:remoteSupported?'0.8.0':'0.7.3',commands:maintenance.map((item,index)=>({command:item.operation==='update'?'software_update':'software_rollback',payload:item.version,status:'queued',id:String(index)}))}));
    if(req.url==='/api/v1/admin/devices/software'&&req.method==='POST'){maintenance.unshift(JSON.parse(body));return res.end(JSON.stringify({command:{status:'queued'}}))}
    if(req.url==='/api/v1/admin/devices')return res.end(JSON.stringify({devices:[device]}));
    if(req.url==='/api/v1/admin/subscriptions')return res.end(JSON.stringify({subscriptions:[]}));
    if(req.url==='/api/v1/admin/rules')return res.end(JSON.stringify({rules:[]}));
    if(req.url==='/api/v1/admin/provider-catalog')return res.end(JSON.stringify({categories:[],profiles:[]}));
    if(req.url==='/api/v1/admin/rule-packages')return res.end(JSON.stringify({packages:[]}));
    if(req.url?.startsWith('/api/v1/'))return res.end('{}');
    res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.TY_UI_BROWSER||'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'});
    const page=await browser.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));page.on('dialog',dialog=>dialog.accept());
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.locator('#tokenInput').fill('admin');await page.locator('#loginBtn').click();
    await page.locator('[data-page="devices"]').first().click();await page.getByRole('button',{name:'查看详情'}).click();
    await page.getByRole('heading',{name:'软件维护 · 管理员'}).waitFor();
    await page.locator('.software-version').fill('0.8.0');await page.locator('.software-channel').selectOption('pilot');
    await page.locator('.software-upgrade').click();
    await page.waitForFunction(()=>document.querySelector('.software-status')?.textContent.includes('已排队'));
    assert.equal(maintenance.length,1);assert.deepEqual(maintenance[0],{device_id:device.id,operation:'update',channel:'pilot',version:'0.8.0',confirm:'UPDATE:0.8.0'});
    await page.locator('.software-rollback-version').fill('0.8.0');await page.locator('.software-rollback').click();
    await page.waitForFunction(()=>document.querySelector('.software-status')?.textContent.includes('回退'));
    assert.equal(maintenance.length,2);assert.deepEqual(maintenance[0],{device_id:device.id,operation:'rollback',channel:'',version:'0.8.0',confirm:'ROLLBACK:0.8.0'});
    remoteSupported=false;await page.locator('.software-refresh').click();
    await page.getByText('这台设备尚未具备可确认的远程维护能力',{exact:false}).waitFor();
    assert.equal(await page.locator('.software-upgrade').isDisabled(),true);
    assert.equal(await page.locator('.software-rollback').isDisabled(),true);
    assert.deepEqual(errors,[]);console.log('PASS: administrator update and rollback require exact version and confirmation');
  }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(error=>{console.error(error);process.exitCode=1});
