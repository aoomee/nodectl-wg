// Run with Node + Playwright. All HTTP calls are mocked; no VPS is contacted.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
(async () => {
 const root = path.resolve(__dirname, '..');
 const component = fs.readFileSync(path.join(root, 'templates/components/traffic_stats_panel_v2.html'), 'utf8').replace(/\{\{define[^}]+\}\}/, '').replace(/\{\{end\}\}\s*$/, '');
 const globalStyles = fs.readFileSync(path.join(root, 'templates/index.html'), 'utf8').match(/<style>[\s\S]*?<\/style>/)[0];
 const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : { channel: 'chrome' });
 try {
  for (const width of [1280, 375]) {
   const page = await browser.newPage({ viewport: { width, height: 1000 } });
   const errors = [], dates = [];
   page.on('pageerror', e => errors.push(e.message));
   await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/') return route.fulfill({ contentType: 'text/html', body: `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${globalStyles}${component}` });
    let body;
    if (url.pathname === '/api/traffic/landing-nodes') body = { status: 'success', nodes: [] };
    else if (url.pathname === '/api/traffic/consumption-rank') {
     const date = url.searchParams.get('date'); dates.push(date);
     body = { status: 'success', rank: { generated_at: date, items: [] } };
    } else if (url.pathname === '/api/traffic/series') body = { status: 'success', points: [] };
    else return route.abort();
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
   });
   await page.routeWebSocket('**/*', () => {});
   await page.goto('http://calendar.test/');
   await page.waitForFunction(() => document.getElementById('ts-status').textContent !== '加载中...');
   assert.equal(await page.locator('#ts-status').textContent(), '', `Initialization failed: ${errors.join('; ')}`);
   const trigger = page.locator('#ts-rank-date-trigger');
   const popover = page.locator('#ts-custom-cal-popover');
   await trigger.click();
   await popover.waitFor({ state: 'visible' });
   const title = await page.locator('#ts-cal-month-title').textContent();
   await page.locator('#ts-cal-prev').click();
   assert.notEqual(await page.locator('#ts-cal-month-title').textContent(), title);
   await page.locator('#ts-cal-next').click();
   assert.equal(await page.locator('#ts-cal-month-title').textContent(), title);
   const box = await popover.boundingBox();
   assert.ok(box.x >= 0 && box.x + box.width <= width + 1, `Calendar overflows ${width}px viewport: ${JSON.stringify(box)}`);
   const day = page.locator('.ts-cal-day[data-date]').first();
   const picked = await day.getAttribute('data-date');
   await Promise.all([
    page.waitForResponse(r => r.url().includes('consumption-rank') && new URL(r.url()).searchParams.get('date') === picked),
    day.click()
   ]);
   await popover.waitFor({ state: 'hidden' });
   await page.waitForFunction(date => document.getElementById('ts-rank-date-label').textContent === date.replace(/-/g, ' / '), picked);
   assert.equal(await page.locator('#ts-rank-date-picker').inputValue(), picked);
   assert.ok(dates.includes(picked));
   await trigger.click();
   await page.locator('#ts-cal-today').click();
   await popover.waitFor({ state: 'hidden' });
   const today = await page.evaluate(() => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; });
   assert.equal(await page.locator('#ts-rank-date-picker').inputValue(), today);
   await trigger.click();
   await page.locator('body').click({ position: { x: 1, y: 1 } });
   await popover.waitFor({ state: 'hidden' });
   assert.deepEqual(errors, []);
   await page.close();
  }
  console.log('Traffic calendar: month navigation, date selection, today, outside close, mobile bounds and JavaScript errors passed.');
 } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exit(1); });
