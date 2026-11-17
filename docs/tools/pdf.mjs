import { chromium } from 'playwright-core';
import { pathToFileURL } from 'node:url';
const [src, out] = process.argv.slice(2);
const browser = await chromium.launch({ channel: 'msedge', headless: true });
const page = await browser.newPage();
await page.goto(pathToFileURL(src).href, { waitUntil: 'networkidle' });
await page.waitForFunction(() => [...document.querySelectorAll('.mermaid')].every((m) => m.querySelector('svg')), null, { timeout: 30000 });
await page.evaluate(() => document.fonts.ready);
await page.waitForTimeout(800);
await page.pdf({ path: out, preferCSSPageSize: true, printBackground: true,
  displayHeaderFooter: true, headerTemplate: '<span></span>',
  footerTemplate: '<div style="width:100%;font-size:7pt;color:#8a8f98;font-family:Segoe UI,sans-serif;padding:0 17mm;display:flex;justify-content:space-between"><span>Stratus Cloud · Envelope Encryption for Cloud Storage</span><span class="pageNumber"></span></div>' });
await browser.close();
console.log('pdf ok');
