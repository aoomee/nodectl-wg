// Render the real edit modal and WG component. All HTTP is mocked; no VPS.
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const baseStyles=fs.readFileSync(path.join(root,'templates/index.html'),'utf8').match(/<style>([\s\S]*?)<\/style>/)[1];
const template=name=>fs.readFileSync(path.join(root,'templates/components',name),'utf8').replace(/\{\{define[^}]+\}\}/,'').replace(/\{\{end\}\}\s*$/,'').replace('{{.Protocols}}',JSON.stringify(['reality','ss','hy2']));
const html=`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${baseStyles}</style><script>
window.allNodesData={}; function loadNodesList(){};
window.streams=[]; window.EventSource=class { constructor(url){this.url=url;streams.push(this)} close(){this.closed=true} };
</script>${template('edit_node_modal.html')}${template('node_wg_editor.html')}`;
const reality='vless://11111111-1111-4111-8111-111111111111@203.0.113.1:443?security=reality&pbk=test&sni=example.com&type=tcp';
const makeNode=(uuid,landing=false)=>({uuid,name:uuid==='a'?'入口 A':'落地 B',routing_type:landing?2:1,ipv4:landing?'203.0.113.2':'203.0.113.1',ipv6:landing?'2001:db8::2':'2001:db8::1',links:landing?{ss:'ss://mock@203.0.113.2:8388'}:{reality},link_ports:landing?{ss:8388}:{reality:443},disabled_links:[],created_at:'2026-10-01',agent_version:'test'});
(async()=>{
 const browser=await chromium.launch(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{channel:'chrome'});
 try {
  for(const width of [1280,375,320]) {
   const page=await browser.newPage({viewport:{width,height:1000}});
   const errors=[],requests=[],ordinary=[],saves=[],alerts=[];
   let pair=null,ready=true,saveFailure=false,optionFailure=false,optionDelay=0,saveDelay=0;
   let diagnostics=false,unavailablePeer=false;
   let nodes=[makeNode('a'),makeNode('b',true)];
   page.on('pageerror',e=>errors.push(e.message));
   page.on('dialog',async d=>{alerts.push(d.message());await d.accept();});
   await page.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(url.pathname==='/')return route.fulfill({contentType:'text/html; charset=utf-8',body:html});
    if(url.pathname==='/api/get-nodes')return route.fulfill({json:{status:'success',data:{direct_nodes:[nodes[0]],land_nodes:[nodes[1]],wg_pairs:pair?{a:{role:'entry',peer_uuid:'b',peer_name:'落地 B',status:pair.status}}:{} }}});
    if(url.pathname==='/api/node/wg/options') {
     if(optionFailure)return route.fulfill({status:503,json:{status:'error',message:'连接检查暂时失败，请刷新重试'}});
     const data={pair:url.searchParams.get('uuid')==='a'?pair:null,ready,peers:[{uuid:'b',name:'落地 B',ready:true},{uuid:'c',name:'落地 C',ready:true}]};
     if(diagnostics) {
      data.readiness={role:'entry',ready,enrollment_mode:'none',checks:[{code:'node',label:'节点条件',ready:true},{code:'protocol',label:'REALITY 部署',ready:true},{code:'agent',label:'Agent 连接',ready,detail:'Agent 未连接；请确认服务器上的 nodectl-agent 服务正在运行。'}]};
      if(unavailablePeer)data.peers[1]={uuid:'c',name:'落地 C <img src=x onerror=alert(1)>',ready:false,readiness:{checks:[{code:'protocol',label:'SS 部署',ready:false,detail:'请先启用并推送 SS，等待成功。'}]}};
     }
     const delay=optionDelay; if(delay)await new Promise(r=>setTimeout(r,delay));
     return route.fulfill({json:{status:'success',data}});
    }
    if(url.pathname==='/api/node/wg/push') {
     assert.equal(req.headers()['x-nodectl-wg'],'1'); const body=req.postDataJSON();requests.push(body);
     pair={...body,id:'mock-pair',topology_version:2,source_protocol:'reality',target_protocol:'ss',restore_direct:!body.enabled,status:body.enabled?'active':'disabled',phase:body.enabled?'active':'disabled'};
     return route.fulfill({json:{status:'success',data:{pair}}});
    }
    if(url.pathname==='/api/update-node') {
     const body=req.postDataJSON();saves.push(body); if(saveDelay)await new Promise(r=>setTimeout(r,saveDelay));
     if(!saveFailure)nodes=nodes.map(n=>n.uuid===body.uuid?{...n,...body}:n);
     return route.fulfill({json:{status:saveFailure?'error':'success',message:saveFailure?'mock save failure':undefined}});
    }
    if(url.pathname==='/api/node/control/push-config') { ordinary.push(req.postDataJSON());return route.fulfill({json:{status:'success',command_id:'cmd-'+ordinary.length}}); }
    errors.push('Unexpected HTTP '+url.pathname);return route.abort();
   });
   const open=async(uuid='a')=>{await page.evaluate(uuid=>openEditModal(uuid),uuid);await page.waitForFunction(()=>nodeWGEditor.loaded);await page.waitForFunction(()=>!isInitializingEdit);};
   const push=async()=>{await page.locator('#btnPushConfig').click();await page.locator('#btnPushConfig').click();await page.waitForFunction(()=>!nodeWGEditor.busy);};
   const selectWG=async(peer='b')=>{await page.locator('#nodeWGMode').selectOption('wg');await page.locator('#nodeWGPeer').selectOption(peer);};
   const complete=async(status='ok')=>{await page.waitForFunction(()=>streams.length>0);await page.evaluate(status=>streams.at(-1).onmessage({data:JSON.stringify({type:'result',status})}),status);};
   await page.goto('https://wg-editor.test/');await open();
   await page.locator('.segment-option[data-type="1"]').focus();await page.keyboard.press('Space');
   assert.equal(await page.locator('.segment-option[data-type="1"]').getAttribute('aria-pressed'),'true');
   assert.equal(await page.locator('.segment-option[data-ipmode="0"]').getAttribute('aria-pressed'),'true','routing selection must preserve the independent IP mode');
   assert.equal(await page.locator('#editNodeIPModeControl .active').count(),1);

   // IP mode sync: selecting single-stack hides per-protocol IP capsule; reverting shows it again.
   await page.locator('.segment-option[data-ipmode="1"]').click();
   assert.equal(await page.locator('.proto-ipmode-capsule').first().isVisible(),false,'single-stack node must hide per-protocol IP mode');
   await page.locator('.segment-option[data-ipmode="0"]').click();
   assert.equal(await page.locator('.proto-ipmode-capsule').first().isVisible(),true,'follow-system dual-stack node must show per-protocol IP mode');
   await page.waitForFunction(()=>editNodeAutoSaveTimer===null && editNodeSaveRunning===0);
   await page.evaluate(()=>{ nodeWGEditor.baseline = nodeWGOrdinarySnapshot(); });

   assert.equal(await page.locator('.protocol-card[data-proto="reality"] #nodeWGCard').count(),1);
   assert.equal(await page.locator('#nodeWGPort').count(),0);
   assert.equal(await page.locator('#protocolListContainer .protocol-card').count(),1);
   await page.evaluate(()=>showAddProtocolMenu());assert.ok(!(await page.locator('#protoSelectList').innerText()).includes('WG'));
   await page.evaluate(()=>document.getElementById('protoSelectOverlay').style.display='none');
   const box=await page.locator('#nodeWGCard').boundingBox();assert.ok(box.x>=-1 && box.x+box.width<=width+1,'outbound must fit viewport');

   // Minimalist de-texted WG card: no redundant tutorial drawers or manual enrollment buttons.
   assert.equal(await page.locator('#nodeWGPeerField').isVisible(),false,'direct must hide landing controls');
   assert.equal(await page.locator('#nodeWGSetupDetails').count(),0);
   assert.equal(await page.locator('#nodeWGUsage').count(),0);
   assert.equal(await page.locator('#nodeWGBind').count(),0,'direct Agent WG requires no manual enrollment button');
   assert.equal(await page.locator('#nodeWGRefresh').isVisible(),true);
   assert.equal(await page.locator('#nodeWGSetup').evaluate(e=>e.classList.contains('is-compact')),true,'ready setup card stays compact');
   await page.locator('#nodeWGRefresh').focus();
   assert.equal(await page.evaluate(()=>document.activeElement.id),'nodeWGRefresh');
   await page.locator('#nodeWGRefresh').evaluate(e=>e.blur());
   if(width>768){
    assert.equal(await page.locator('#protocolListContainer').evaluate(e=>getComputedStyle(e).overflowY),'visible');
    assert.equal(await page.locator('.edit-right-col').evaluate(e=>getComputedStyle(e).overflowY),'auto');
   }

   optionFailure=true;await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGSetupBadge').innerText(),'检查中','failed refresh must not retain a green ready badge');
   assert.match(await page.locator('#nodeWGSetupStatus').innerText(),/刷新重试/);
   optionFailure=false;await page.locator('#nodeWGRefresh').click();await page.waitForFunction(()=>nodeWGEditor.loaded);

   // Backend reasons, unavailable peers, safe text rendering and stale-state clearing.
   diagnostics=true;ready=false;unavailablePeer=true;await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGChecks .node-wg-check').count(),1,'only failing checks are shown');
   assert.match(await page.locator('#nodeWGChecks').innerText(),/Agent 未连接/);
   await page.locator('#nodeWGMode').selectOption('wg');
   assert.equal(await page.locator('#nodeWGPeer option[value="c"]').isDisabled(),true);
   await page.locator('#nodeWGPeerIssues summary').click();
   assert.match(await page.locator('#nodeWGPeerIssues').innerText(),/请先启用并推送 SS/);
   assert.equal(await page.locator('#nodeWGPeerIssues img').count(),0,'node names must remain plain text');
   await page.locator('#nodeWGPeerIssuesSummary').focus();await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGPeerIssues').evaluate(e=>e.open),true,'refresh preserves expanded reasons');
   assert.equal(await page.evaluate(()=>document.activeElement.id),'nodeWGPeerIssuesSummary');
   const checkBox=await page.locator('#nodeWGChecks').boundingBox();assert.ok(checkBox.x>=0 && checkBox.x+checkBox.width<=width+1);
   optionFailure=true;await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGChecks .node-wg-check').count(),0,'failed refresh must clear stale checks');
   assert.equal(await page.locator('#nodeWGPeerIssues').isVisible(),false);
   optionFailure=false;ready=true;unavailablePeer=false;await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGChecks').isVisible(),false,'all ready collapses checks');
   assert.equal(await page.locator('#nodeWGPeerIssues').isVisible(),false);
   await page.locator('#nodeWGMode').selectOption('direct');diagnostics=false;

   // Direct retains the ordinary endpoint and awaits a real command result.
   await push();await page.waitForFunction(()=>streams.length===1);
   assert.deepEqual(ordinary[0],{uuid:'a',protocols:['reality'],ports:{reality:443}});assert.equal(requests.length,0);
   assert.equal(await page.locator('#nodeWGSetup').isVisible(),false,'setup must not crowd the command log');
   await page.evaluate(()=>{nodeWGEditor.mode='wg';nodeWGEditor.peer='b';pushConfigToAgent();});assert.equal(requests.length,0,'accepted is not success');
   await complete();await page.waitForFunction(()=>!nodeWGEditor.ordinaryPending);await page.evaluate(()=>closeCmdLogPanel());
   await selectWG();await push();await page.waitForFunction(()=>nodeWGEditor.pair?.status==='active');
   assert.deepEqual(requests[0],{uuid:'a',peer_uuid:'b',entry_port:443,revision:1,enabled:true});
   await push();assert.equal(requests.length,1,'unchanged active is a no-op');assert.equal(ordinary.length,1);

   // Refresh/poll preserves both unsaved mode and peer, even while pair is active.
   await page.locator('#nodeWGPeer').selectOption('c');await page.locator('#nodeWGPeer').focus();await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGPeer').inputValue(),'c');
   assert.equal(await page.evaluate(()=>document.activeElement.id),'nodeWGPeer','poll must preserve the focused selection');
   await page.locator('#nodeWGMode').selectOption('direct');await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGMode').inputValue(),'direct');await selectWG('b');

   // Active edits cannot autosave or silently push only WG / switch to direct.
   const saveCount=saves.length;
   await page.locator('#editNodeName').fill('Changed A');await page.evaluate(()=>markAsModified());
   await push();assert.equal(ordinary.length,1);assert.equal(requests.length,1);assert.equal(saves.length,saveCount);
   assert.match(await page.locator('#nodeWGStatus').innerText(),/停用清理/);
   await page.locator('#nodeWGCleanup').click();await page.waitForFunction(()=>nodeWGEditor.pair?.status==='disabled');
   assert.equal(requests[1].enabled,false);assert.equal(requests[1].revision,2);
   assert.equal(ordinary.length,1,'cleanup never also applies ordinary edits');
   await selectWG();await push();assert.equal(requests.length,2,'dirty new WG must not ordinary-apply first');
   assert.match(await page.locator('#nodeWGStatus').innerText(),/普通配置变更/);
   assert.equal(await page.locator('#nodeWGStatus').getAttribute('data-tone'),'error');

   // Accessible staged preparation: autosave -> ordinary command -> SSE -> WG-only.
   await page.locator('#nodeWGMode').selectOption('direct');saveDelay=120;
   await push();await page.waitForFunction(()=>streams.length===2);saveDelay=0;
   assert.equal(saves.at(-1).name,'Changed A');assert.equal(ordinary.length,2);
   await complete('error');await page.waitForFunction(()=>!nodeWGEditor.ordinaryPending);await page.evaluate(()=>closeCmdLogPanel());
   await selectWG();await push();assert.equal(requests.length,2);assert.match(await page.locator('#nodeWGStatus').innerText(),/未确认成功/);
   await page.locator('#nodeWGMode').selectOption('direct');await push();await page.waitForFunction(()=>streams.length===3);await complete();await page.waitForFunction(()=>!nodeWGEditor.ordinaryPending);await page.evaluate(()=>closeCmdLogPanel());
   await selectWG();await push();await page.waitForFunction(()=>nodeWGEditor.pair?.status==='active');assert.equal(requests.length,3);assert.equal(ordinary.length,3);

   // Restart recovery polls without replaying deployment, retaining the user's draft.
   pair={...pair,status:'recovering',phase:'verify_active'};await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGPairBadge').innerText(),'恢复核验');
   assert.match(await page.locator('#nodeWGStatus').innerText(),/面板重启后正在核验双端连接/);
   assert.equal(await page.locator('#nodeWGCleanup').isVisible(),true);
   await push();assert.equal(requests.length,3);assert.equal(ordinary.length,3);
   await page.locator('#nodeWGPeer').selectOption('c');await page.locator('#nodeWGMode').selectOption('direct');
   const pollRequest=await page.evaluate(()=>nodeWGEditor.request);
   pair={...pair,status:'active',phase:'active'};
   await page.waitForFunction(n=>nodeWGEditor.request>n && nodeWGEditor.pair.status==='active',pollRequest);
   assert.equal(await page.locator('#nodeWGPeer').inputValue(),'c');assert.equal(await page.locator('#nodeWGMode').inputValue(),'direct');
   await selectWG('b');

   // Failed/disabled fail-closed pair still requires explicit restore direct.
   pair={...pair,enabled:false,status:'disabled',phase:'blocked',restore_direct:false};await page.evaluate(()=>loadNodeWGEditor('a'));
   assert.equal(await page.locator('#nodeWGPairBadge').innerText(),'已阻断');
   assert.match(await page.locator('#nodeWGStatus').innerText(),/已阻断/);
   await page.locator('#nodeWGRetry').click();await page.waitForFunction(()=>nodeWGEditor.pair?.status==='active');
   assert.equal(requests.at(-1).retry_blocked,true);assert.equal(requests.at(-1).enabled,true);
   assert.equal(await page.locator('#nodeWGRetry').isVisible(),false);
   pair={...pair,enabled:false,status:'disabled',phase:'blocked',restore_direct:false};await page.evaluate(()=>loadNodeWGEditor('a'));
   await page.locator('#nodeWGCleanup').click();await page.waitForFunction(()=>nodeWGEditor.pair?.restore_direct);
   assert.equal(requests.at(-1).enabled,false);

   // New WG cannot proceed on failed autosave or backend readiness.
   pair=null;await page.evaluate(()=>closeEditModal());await open();saveFailure=true;
   await page.evaluate(()=>triggerNodeAutoSave(true));await page.waitForFunction(()=>editNodeSaveFailed && editNodeSaveRunning===0);
   await selectWG();const before=requests.length;await push();assert.equal(requests.length,before);assert.match(await page.locator('#nodeWGStatus').innerText(),/保存失败/);
   saveFailure=false;await page.evaluate(()=>triggerNodeAutoSave(true));await page.waitForFunction(()=>!editNodeSaveFailed && editNodeSaveRunning===0 && editNodeAutoSaveTimer===null);
   ready=false;await push();assert.equal(requests.length,before);assert.match(await page.locator('#nodeWGStatus').innerText(),/未就绪/);ready=true;
   assert.equal(await page.locator('#nodeWGSetupBadge').innerText(),'待就绪');

   // Superseded options and close cannot resurrect stale state.
   optionDelay=180;await page.evaluate(()=>{window.oldOptions=loadNodeWGEditor('a')});
   await page.waitForTimeout(30);optionDelay=0;pair={uuid:'a',peer_uuid:'b',entry_port:443,revision:9,enabled:true,status:'active',phase:'active',topology_version:2};
   await page.evaluate(()=>loadNodeWGEditor('a'));await page.evaluate(()=>window.oldOptions);assert.equal(await page.evaluate(()=>nodeWGEditor.pair.revision),9);
   await page.evaluate(()=>closeEditModal());
   assert.equal(await page.locator('#nodeWGSetup').count(),0);assert.equal(await page.evaluate(()=>nodeWGEditor.timer),null);

   // Legacy pair without REALITY exposes cleanup only, not a fake protocol.
   nodes[0]={...makeNode('a'),links:{ss:'ss://mock'},link_ports:{ss:8388}};
   pair={uuid:'a',peer_uuid:'b',entry_port:24443,revision:11,enabled:true,status:'active',phase:'active',topology_version:1};
   await open();assert.equal(await page.locator('#protocolListContainer #nodeWGCard').count(),0);
   assert.equal(await page.locator('#nodeWGChoices').isVisible(),false);assert.match(await page.locator('#nodeWGTopology').innerText(),/旧版配对/);
   await push();assert.equal(requests.length,before);await page.locator('#nodeWGCleanup').click();await page.waitForFunction(()=>nodeWGEditor.pair.status==='disabled');
   assert.equal(requests.at(-1).enabled,false);

   // Landing shows compact readiness bar without fake WG card; empty protocol placeholder clears on insert.
   await page.evaluate(()=>closeEditModal());await open('b');
   assert.equal(await page.locator('#nodeWGCard').count(),0);
   assert.equal(await page.locator('#nodeWGSetupBadge').innerText(),'落地就绪');
   const overflow=await page.locator('#editNodeModal').evaluate(e=>Array.from(e.querySelectorAll('#nodeWGSetup, .edit-footer')).some(el=>el.scrollWidth>el.clientWidth+1));
   assert.equal(overflow,false,'readiness bar and footer must fit narrow screens');
   await page.evaluate(()=>closeEditModal());
   assert.deepEqual(errors,[]);await page.close();
  }
  console.log('PASS: real modal at 1280/375/320px, IP mode sync, minimalist Agent WG UI, high-contrast status tones, auto-refresh, and fail-closed guards.');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
