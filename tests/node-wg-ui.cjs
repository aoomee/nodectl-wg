// Isolated mocked UI: never contacts a VPS or creates real enrollment tokens.
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
(async()=>{
 const root=path.resolve(__dirname,'..');
 const component=fs.readFileSync(path.join(root,'templates/components/node_wg_editor.html'),'utf8').replace(/\{\{define[^}]+\}\}/,'').replace(/\{\{end\}\}\s*$/,'');
 const browser=await chromium.launch(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{channel:'chrome'});
 try {
  for(const width of [1280,375]) {
   const page=await browser.newPage({viewport:{width,height:1000}});const errors=[],requests=[];let pair=null;
   page.on('pageerror',e=>errors.push(e.message));
   await page.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(url.pathname==='/')return route.fulfill({contentType:'text/html; charset=utf-8',body:`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><input id="editNodeUUID" value="a"><div id="protocolListContainer"></div><button id="btnPushConfig" onclick="pushNodeWGConfig()">推送配置</button><script>function updateLayoutState(){};async function waitForNodeAutoSave(){};</script>${component}`});
    if(url.pathname==='/api/node/wg/options')return route.fulfill({json:{status:'success',data:{pair,peers:[{uuid:'b',name:'落地 B',ready:true}],ready:true}}});
    if(url.pathname==='/api/node/wg/push'){
     assert.equal(req.headers()['x-nodectl-wg'],'1');const body=req.postDataJSON();requests.push(body);
     pair={...body,id:'0123456789abcdef',status:body.enabled?'active':'disabled',phase:body.enabled?'active':'disabled'};
     return route.fulfill({json:{status:'success',data:{pair}}});
    }
    throw Error('Unexpected request '+url.pathname);
   });
   await page.goto('https://wg-editor.test/');
   await page.evaluate(async()=>{await loadNodeWGEditor('a');addNodeWGCard();});
   await page.locator('#nodeWGPeer').selectOption('b');
   await page.locator('#nodeWGPort').fill('24443');
   await page.locator('#btnPushConfig').click();
   await page.waitForFunction(()=>document.getElementById('nodeWGStatus').textContent.includes('active'));
   assert.equal(requests[0].peer_uuid,'b');assert.equal(requests[0].revision,1);
   assert.equal(await page.locator('#protocolListContainer .protocol-card').count(),0,'WG card must not enter generic protocol serialization');
   const box=await page.locator('#nodeWGCard').boundingBox();assert.ok(box.x+box.width<=width+1);
   await page.locator('#nodeWGEnabled').uncheck();await page.locator('#btnPushConfig').click();
   await page.waitForFunction(()=>document.getElementById('nodeWGStatus').textContent.includes('disabled'));
   assert.equal(requests[1].enabled,false);assert.equal(requests[1].revision,2);
   await page.evaluate(()=>resetNodeWGEditor());assert.equal(await page.locator('#nodeWGCard').count(),0);
   assert.deepEqual(errors,[]);await page.close();
  }
  console.log('Node WG editor: pairing, revision, disable, isolated serialization, mobile bounds and cleanup passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
