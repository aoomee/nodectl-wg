const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const modal=fs.readFileSync(path.join(root,'templates/components/pwd_modal.html'),'utf8').replace(/\{\{define[^}]+\}\}/,'').replace(/\{\{end\}\}\s*$/,'');
(async()=>{
 const browser=await chromium.launch(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{channel:'chrome'});
 try{
  for(const width of [1280,375]){
   const page=await browser.newPage({viewport:{width,height:900}}),requests=[],errors=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.route('**/*',route=>{
    const req=route.request(),url=new URL(req.url());
    if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'+modal});
    if(url.pathname==='/api/change-password'){requests.push(req.postDataJSON());return route.fulfill({json:{status:'error',message:'测试响应，请重试'}});}
    errors.push(url.pathname);return route.abort();
   });
   await page.goto('https://password.test/');await page.evaluate(()=>openPwdModal());
   await page.locator('#oldUsername').fill('admin');await page.locator('#oldPwd').fill('admin');
   const enter=async value=>{await page.locator('#newPwd').fill(value);await page.locator('#confirmPwd').fill(value);};
   await enter('short');await page.locator('#pwdSubmitBtn').click();
   assert.equal(await page.locator('#newPwd').evaluate(e=>e.validity.tooShort),true);assert.equal(requests.length,0);
   await enter('界'.repeat(25));await page.locator('#pwdSubmitBtn').click();
   assert.match(await page.locator('#pwdIndicator').innerText(),/72 字节/);assert.equal(requests.length,0);
   await enter('long-private-password');await page.locator('#pwdSubmitBtn').click();
   await page.waitForFunction(()=>document.getElementById('pwdIndicator').textContent.includes('测试响应'));
   assert.equal(requests.length,1);assert.equal(requests[0].old_password,'admin','legacy current passwords remain usable for rotation');
   assert.equal(requests[0].new_password,'long-private-password');
   // Username-only edits must not require or silently send a new password.
   await page.evaluate(()=>openPwdModal());await page.locator('#oldUsername').fill('admin');await page.locator('#oldPwd').fill('admin');await page.locator('#newUsername').fill('new-admin');
   await page.locator('#pwdSubmitBtn').click();await page.waitForFunction(()=>document.getElementById('pwdIndicator').textContent.includes('测试响应'));
   assert.equal(requests.length,2);assert.equal(requests[1].new_password,'');assert.equal(requests[1].new_username,'new-admin');
   assert.deepEqual(errors,[]);await page.close();
  }
  console.log('PASS: password policy at desktop/mobile, bcrypt byte limit, legacy current password and username-only changes.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
