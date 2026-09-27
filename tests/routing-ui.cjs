// Browser regression for the local customer routing panel. This uses only mock
// API responses and never connects to a gateway or changes LAN settings.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const html = fs.readFileSync(path.join(__dirname, '../internal/localadmin/web/index.html'), 'utf8');
  const nodes = [
    {id:'aaaaaaaaaaaaaaaa',name:'香港-A',region:'HK'},
    {id:'bbbbbbbbbbbbbbbb',name:'美国-B',region:'US'},
    {id:'cccccccccccccccc',name:'香港-C',region:'HK'},
  ];
  const writes = [];
  const customer = {
    device:{id:'routing-fixture',profile:'managed_geo',config_version:1},
    categories:['China','HK-Broker','AI','Final'],
    nodes,
    preferences:{},
    rules:[],
    rule_packages:[{id:'managed_geo',name:'GeoIP',available:true,version:'a'.repeat(64),published_at:'2026-09-24T00:00:00Z'}],
  };
  const server = http.createServer(async (req,res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    res.setHeader('Content-Type','application/json');
    if(req.url==='/api/status') return res.end(JSON.stringify({setup_required:false,recovery_enabled:false}));
    if(req.url==='/api/session') return res.end(JSON.stringify({device_code:'TESTDEVICE',interface:'eth0',addresses:['192.168.0.10/24'],default_gateway:'192.168.0.1'}));
    if(req.url==='/api/customer/me') return res.end(JSON.stringify(customer));
    if(req.url==='/api/customer/node-preference' && req.method==='POST') {
      const request = JSON.parse(body);
      writes.push(request);
      customer.preferences[request.category]=request.node_id;
      customer.device.config_version++;
      return res.end(JSON.stringify({preferences:customer.preferences,config_version:customer.device.config_version}));
    }
    if(req.url==='/api/network/settings') return res.end(JSON.stringify({settings:{plan:{address_cidr:'192.168.0.10/24',gateway:'192.168.0.1',dhcp_enabled:false,dns_mode:'router'},dns_enabled:false,reservations:[]}}));
    if(req.url==='/api/proxy') return res.end(JSON.stringify({enabled:false,daemon_active:false}));
    res.setHeader('Content-Type','text/html; charset=utf-8');
    res.end(html);
  });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  let browser;
  try {
    browser = await chromium.launch({headless:true,executablePath:process.env.TY_UI_BROWSER || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'});
    const page = await browser.newPage({viewport:{width:1200,height:900}});
    const pageErrors=[];
    page.on('pageerror',error=>pageErrors.push(error.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.locator('[data-local-tab="proxy"]').click();
    const categories=page.locator('#customer-node-categories .routing-category-card');
    try { await categories.first().waitFor({timeout:5000}); }
    catch(error) {
      console.error('page errors:',pageErrors);
      console.error('app visible:',await page.locator('#appView').isVisible());
      console.error('customer sync:',await page.locator('#customer-sync-status').allTextContents());
      console.error('category markup:',await page.locator('#customer-node-categories').allTextContents());
      throw error;
    }
    assert.equal(await categories.count(),4);
    assert.equal(await page.locator('#customer-node-categories').getByText(/救援|内网|LAN/).count(),0);

    await categories.filter({hasText:'AI 服务'}).locator('.routing-category-trigger').click();
    let selected=page.locator('#customer-node-categories .routing-category-card.selected');
    await selected.getByRole('button',{name:/地区自动/}).click();
    await selected.locator('#customer-region-choices').getByRole('button',{name:/香港/}).click();
    await selected.getByRole('button',{name:'保存此分类'}).click();
    await selected.getByText('设备已确认应用此分类的连接方式。').waitFor();
    assert.deepEqual(writes[0],{category:'AI',node_id:'@region:HK'});

    await categories.filter({hasText:'港澳证券'}).locator('.routing-category-trigger').click();
    selected=page.locator('#customer-node-categories .routing-category-card.selected');
    await selected.getByRole('button',{name:/主备容灾/}).click();
    await selected.locator('#customer-actual-nodes').getByRole('button',{name:/香港-A/}).click();
    await selected.locator('#customer-actual-nodes').getByRole('button',{name:/美国-B/}).click();
    await selected.getByRole('button',{name:'保存此分类'}).click();
    await selected.getByText('设备已确认应用此分类的连接方式。').waitFor();
    assert.deepEqual(writes[1],{category:'HK-Broker',node_id:'@failover:aaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbb'});
    assert.deepEqual(pageErrors,[]);
    console.log('PASS: hidden system routes, region choice, failover choice, cloud save and device confirmation');
  } finally {
    if(browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error=>{console.error(error);process.exitCode=1});
