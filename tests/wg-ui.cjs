// Run with Node + Playwright. All HTTP calls are mocked; no VPS is contacted.
const {chromium}=require('playwright');
const fs=require('fs');const path=require('path');const assert=require('node:assert/strict');
(async()=>{
 const root=path.resolve(__dirname,'..');
 const component=fs.readFileSync(path.join(root,'templates/components/wg_relay_modal.html'),'utf8').replace('{{define "wg_relay_modal.html"}}','').replace(/\{\{end\}\}\s*$/,'');
 const base=fs.readFileSync(path.join(root,'templates/components/custom_nodes_modal.html'),'utf8').match(/<style>[\s\S]*?<\/style>/)[0];
 const browser=await chromium.launch(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{channel:'chrome'});
 try{
 const page=await browser.newPage({viewport:{width:1280,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 let jobs=[],requests=[],imports=0;
 await page.route('http://wg.test/**',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.pathname==='/'){return route.fulfill({contentType:'text/html',body:`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:Arial,sans-serif}</style>${base}<button onclick="openWGRelayModal()">打开 WG 中转</button>${component}`});}
  let result;
  if(url.pathname.endsWith('/jobs'))result={jobs};
  else if(url.pathname.endsWith('/job'))result=jobs.find(j=>j.id===url.searchParams.get('id'));
  else if(url.pathname.endsWith('/start')){
   const data=req.postDataJSON();requests.push(data);assert.equal(req.headers()['x-nodectl-wg'],'1');
   const spec={...data};delete spec.a_password;delete spec.b_password;
   const j={id:'job-'+jobs.length,spec,status:'running',created:new Date().toISOString(),log:'正在连接…'};jobs.unshift(j);result=j;
  }else if(url.pathname.endsWith('/import')){imports++;result={message:'已加入自定义节点与订阅'};}
  else if(url.pathname.endsWith('/cancel')){jobs[0].status='cancelled';result={ok:true};}
  else throw Error('Unexpected route: '+url.pathname);
  await route.fulfill({contentType:'application/json',body:JSON.stringify(result)});
 });
 await page.goto('http://wg.test/');await page.getByText('打开 WG 中转',{exact:true}).click();
 await page.locator('#wgAIP').fill('8.8.8.8');await page.locator('#wgBIP').fill('1.1.1.1');
 await page.locator('#wgAPass').fill('secret-a');await page.locator('#wgBPass').fill('secret-b');
 await page.locator('#wgCheck').click();await page.waitForFunction(()=>document.getElementById('wgAPass').value==='');
 assert.equal(requests[0].mode,'check');assert.equal(requests[0].a_ssh,22);
 jobs[0].status='succeeded';jobs[0].result={kind:'check'};jobs[0].log='SSH、系统和端口检查通过。';
 await page.waitForFunction(()=>document.getElementById('wgStatus').textContent.includes('预检完成'));
 assert.equal(await page.locator('#wgResult').isVisible(),false);
 await page.locator('#wgArchitecture').selectOption('vless_ss');await page.locator('#wgAPass').fill('secret-a');await page.locator('#wgBPass').fill('secret-b');
 await page.locator('#wgDeploy').click();await page.waitForFunction(()=>document.getElementById('wgAPass').value==='');
 assert.equal(requests[1].architecture,'vless_ss');assert.equal(requests[1].mode,'deploy');
 jobs[0].status='succeeded';jobs[0].result={kind:'deploy',link:'vless://verified@8.8.8.8:443#VLESS-WG-SS'};jobs[0].log='1/5 安装落地\n5/5 HTTPS、出口 IP 和文件下载校验通过。';
 await page.locator('#wgImport').waitFor({state:'visible'});await page.locator('#wgImport').click();await page.waitForFunction(()=>document.getElementById('wgMessage').textContent.includes('已加入'));assert.equal(imports,1);
 await page.locator('.wg-body').evaluate(e=>e.scrollTop=0);
 fs.mkdirSync(path.join(root,'outputs'),{recursive:true});await page.screenshot({path:path.join(root,'outputs/wg-desktop.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});await page.locator('.wg-body').evaluate(e=>e.scrollTop=0);await page.screenshot({path:path.join(root,'outputs/wg-mobile.png'),fullPage:true});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
 await page.keyboard.press('Escape');assert.equal(await page.locator('#wgRelayModal').isVisible(),false);
 assert.deepEqual(errors,[]);console.log('WG UI: check, deploy, mode selection, credential clearing, import, mobile layout and keyboard close passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
