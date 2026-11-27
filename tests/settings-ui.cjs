// Exercise the real settings-save functions with a minimal DOM and mocked API.
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
function source(file,name){
 const text=fs.readFileSync(path.join(root,'templates/components',file),'utf8');
 const declarations=[...text.matchAll(/^    (?:async )?function (\w+)\(/gm)];
 const index=declarations.findIndex(m=>m[1]===name);assert.ok(index>=0,name);
 return text.slice(declarations[index].index,declarations[index+1]?.index ?? text.indexOf('</script>',declarations[index].index));
}
const code=[
 ['system_settings_modal.html','triggerSysAutoSave'],['system_settings_modal.html','confirmTokenSave'],['system_settings_modal.html','loadAllSystemSettings'],
 ['global_settings_modal.html','triggerGsAutoSave'],['sub_links_modal.html','saveCustomSubNameDebounced'],
 ['cf_modal.html','cftShowSaveIndicator'],['cf_modal.html','cftTunnelAutoUpdateToggle'],['cf_modal.html','cftIPOptAutoUpdateToggle']
].map(([file,name])=>source(file,name)).join('\n');
const ids=new Set([...code.matchAll(/getElementById\(\s*['"]([^'"]+)['"]/g)].map(m=>m[1]));
['sys_tg_bot_token','testTokenButton'].forEach(id=>ids.add(id));
const markup=[...ids].map(id=>/Modal$|Indicator$/.test(id)?`<div id="${id}" class="active"></div>`:id==='testTokenButton'?`<button id="${id}">确认</button>`:`<input id="${id}" value="100">`).join('');
const html=`<!doctype html><meta charset="utf-8">${markup}<script>
 let sysAutoSaveTimer=null,gsAutoSaveTimer=null,subNameSaveTimer=null,sysSettingsLoaded=true,gsSettingsLoaded=true,tgBotWhitelistItems=[],currentFormatKey=null;
 function collectSysDefaultInstallProtocols(){return 'reality'}
 function loadNodesList(){} function resetTokenConfirmBtn(){} function renderRightPanel(){} function resizeSubLinkTextarea(){}
 ${code}
</script>`;
(async()=>{
 const browser=await chromium.launch(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{channel:'chrome'});
 try{
  const page=await browser.newPage(),errors=[],requests=[];let status='error',httpStatus=200;
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',route=>{
   const url=new URL(route.request().url());
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
   if(url.pathname==='/api/get-settings')return route.fulfill({status:503,json:{status:'error',message:'设置读取失败'}});
   if(url.pathname==='/api/update-settings'){requests.push(route.request().postDataJSON());return route.fulfill({status:httpStatus,json:{status,message:'保存失败 <img src=x onerror=alert(1)>'}});}
   errors.push(url.pathname);return route.abort();
  });
  const cases=[['triggerSysAutoSave','sysSaveIndicator'],['triggerGsAutoSave','gsSaveIndicator'],['saveCustomSubNameDebounced','subSaveIndicator'],['cftTunnelAutoUpdateToggle','cftSaveIndicator'],['cftIPOptAutoUpdateToggle','cftSaveIndicator']];
  for(const [fn,indicator] of cases){
   await page.goto('https://settings.test/');
   for(const http of [200,500]){
    status='error';httpStatus=http;const before=requests.length;
    await page.evaluate(fn=>window[fn](),fn);
    await page.waitForFunction(id=>document.getElementById(id).textContent.includes('保存失败'),indicator);
    assert.equal(requests.length,before+1);assert.equal(await page.locator('#'+indicator+' img').count(),0);
    assert.ok(!(await page.locator('#'+indicator).innerText()).includes('已保存'));
   }
   status='success';httpStatus=200;await page.evaluate(fn=>window[fn](),fn);
   await page.waitForFunction(id=>document.getElementById(id).textContent.includes('已保存'),indicator);
  }
  await page.goto('https://settings.test/');
  await page.locator('#sys_tg_bot_token').evaluate(e=>{e.value='new-token';e.dataset.original='old-token'});
  status='error';await page.evaluate(()=>confirmTokenSave('sys_tg_bot_token','testTokenButton'));
  assert.equal(await page.locator('#testTokenButton').innerText(),'失败');
  assert.equal(await page.locator('#sys_tg_bot_token').getAttribute('data-original'),'old-token');
  status='success';await page.evaluate(()=>confirmTokenSave('sys_tg_bot_token','testTokenButton'));
  assert.match(await page.locator('#testTokenButton').innerText(),/已保存/);
  assert.equal(await page.locator('#sys_tg_bot_token').getAttribute('data-original'),'new-token');
  // A failed initial load must prevent bulk saves of empty/default controls.
  const before=requests.length;await page.evaluate(()=>{triggerSysAutoSave();return loadAllSystemSettings()});
  assert.match(await page.locator('#sysSaveIndicator').innerText(),/设置读取失败/);
  await page.evaluate(()=>{triggerSysAutoSave();gsSettingsLoaded=false;triggerGsAutoSave()});
  await page.waitForTimeout(750);assert.equal(requests.length,before);
  assert.match(await page.locator('#gsSaveIndicator').innerText(),/尚未加载/);
  assert.deepEqual(errors,[]);console.log('PASS: all six settings-save paths reject HTTP/JSON errors, show plain-text failures, preserve unsaved tokens, and block bulk saves after failed loading.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
