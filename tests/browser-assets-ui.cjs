// Real bundled libraries and production drag/QR code paths; no external network.
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),http=require('http'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const index=fs.readFileSync(path.join(root,'templates/index.html'),'utf8');
const sortableTag=index.match(/<script src="\/assets\/vendor\/sortable-[^>]+><\/script>/)[0];
const dragCode=index.slice(index.indexOf('function initDragAndDrop()'),index.indexOf('function showErrorState('));
const subscription=fs.readFileSync(path.join(root,'templates/components/sub_links_modal.html'),'utf8')
 .replace(/\{\{define[^}]+\}\}/,'').replace(/\{\{end\}\}\s*$/,'');
const manifest=JSON.parse(fs.readFileSync(path.join(root,'internal/webassets/vendor/manifest.json'),'utf8'));
const item=id=>`<div class="node-item" data-uuid="${id}"><button class="drag-handle">拖动 ${id}</button></div>`;
const html=`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
 <style>body{font-family:sans-serif;margin:20px}.lists{display:flex;gap:20px}.list{width:220px;min-height:200px;border:1px solid #ccc}.node-item{height:70px;padding:10px;box-sizing:border-box}.drag-handle{height:44px;width:100%;cursor:grab}</style>
 ${sortableTag}<div class="lists"><div class="list" id="direct-nodes-list">${item('a')}${item('b')}</div><div class="list" id="land-nodes-list">${item('c')}${item('d')}</div></div>
 ${subscription}<script>${dragCode}\ninitDragAndDrop();</script>`;

(async()=>{
 const orders=[],external=[],errors=[];
 const server=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname==='/') {res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html);}
  const asset=manifest.find(a=>url.pathname==='/assets/vendor/'+a.file);
  if(asset) {res.setHeader('Content-Type','text/javascript; charset=utf-8');return res.end(fs.readFileSync(path.join(root,'internal/webassets/vendor',asset.file)));}
  res.setHeader('Content-Type','application/json');
  if(url.pathname==='/api/get-settings')return res.end(JSON.stringify({status:'success',data:{sub_token:'test-subscription',sub_custom_name:'测试订阅'}}));
  if(url.pathname==='/api/reorder-nodes'){
   let data='';req.on('data',b=>data+=b);req.on('end',()=>{orders.push(JSON.parse(data));res.end(JSON.stringify({status:'success'}));});return;
  }
  res.statusCode=404;res.end('{}');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 let browser;
 try {
  const origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launch(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{channel:'chrome'});
  const page=await browser.newPage({viewport:{width:1100,height:900}});
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',route=>{
   if(new URL(route.request().url()).origin!==origin){external.push(route.request().url());return route.abort();}
   return route.continue();
  });
  await page.goto(origin);
  assert.equal(await page.evaluate(()=>Sortable.version),'1.15.7');
  const drag=async(from,to)=>{
   const a=await page.locator(from+' .drag-handle').boundingBox(),b=await page.locator(to).boundingBox();
   await page.mouse.move(a.x+a.width/2,a.y+a.height/2);await page.mouse.down();
   await page.mouse.move(a.x+a.width/2+10,a.y+a.height/2+10,{steps:5});
   await page.mouse.move(b.x+b.width/2,b.y+b.height-5,{steps:25});
   await page.waitForTimeout(300);await page.mouse.up();
  };
  const reordered=page.waitForResponse(r=>r.url().endsWith('/api/reorder-nodes'));
  await drag('[data-uuid="a"]','[data-uuid="b"]');
  await page.waitForFunction(()=>Array.from(document.querySelectorAll('#direct-nodes-list .node-item')).map(e=>e.dataset.uuid).join(',')==='b,a');
  await reordered;
  assert.ok(orders.some(o=>o.target_routing_type===1 && o.node_uuids.join(',')==='b,a'),'drag must save the new order');
  const moved=Promise.all([1,2].map(group=>page.waitForResponse(r=>r.url().endsWith('/api/reorder-nodes') && r.request().postDataJSON().target_routing_type===group)));
  await drag('[data-uuid="a"]','[data-uuid="d"]');
  await page.waitForFunction(()=>!!document.querySelector('#land-nodes-list [data-uuid="a"]'));
  await moved;
  assert.ok(orders.some(o=>o.target_routing_type===2 && o.node_uuids.join(',')==='c,d,a'),'destination group must be saved');
  assert.ok(orders.some(o=>o.target_routing_type===1 && o.node_uuids.join(',')==='b'),'source group must be saved');
  for(const width of [1100,375]){
   await page.setViewportSize({width,height:900});
   await page.evaluate(()=>openSubLinksModal());
   await page.waitForSelector('#qrCodeContainer canvas',{state:'attached'});
   for(const format of ['clash','v2ray']){
    if(format==='v2ray')await page.locator('#wrap_v2ray .sub-format-card').click();
    const link=origin+'/sub/'+format+'?token=test-subscription';
    assert.equal(await page.locator('#currentSubLinkText').inputValue(),link);
    assert.equal(await page.locator('#qrCodeContainer').getAttribute('title'),link);
    assert.ok(await page.locator('#qrCodeContainer canvas').evaluate(canvas=>{
     const pixels=canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height).data;
     let dark=0,light=0;for(let i=0;i<pixels.length;i+=4){if(pixels[i]<100)dark++;if(pixels[i]>240)light++;}
     return dark>100 && light>100;
    }),'QR must contain an actual matrix');
   }
   await page.evaluate(()=>closeSubLinksModal());
  }
  assert.deepEqual(external,[],'browser must not request external dependencies');
  assert.deepEqual(errors,[]);
  console.log('PASS: bundled scripts/SRI, real drag reorder and cross-group save, desktop/mobile QR rendering, no external requests.');
 } finally {if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exit(1)});
