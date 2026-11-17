// Captures documentation screenshots of the running local app with headless Edge.
import { chromium } from 'playwright-core';
import { mkdirSync, writeFileSync } from 'node:fs';

const OUT = process.argv[2];
const BASE = 'http://localhost:5173';
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ channel: 'msedge', headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.5, colorScheme: 'light' });
const page = await ctx.newPage();
const sleep = (ms) => page.waitForTimeout(ms);
const shot = async (name, opts = {}) => {
  await page.screenshot({ path: `${OUT}/${name}.png`, ...opts });
  console.log('saved', name);
};

// ---------------- landing
await page.goto(BASE + '/');
await page.evaluate(() => localStorage.setItem('stratus.theme', 'light'));
await page.waitForFunction(() => document.querySelector('.lp-file')?.className.includes('sealing'), null, { timeout: 15000 });
await page.waitForFunction(() => document.querySelector('.lp-file')?.className.includes('sealed'), null, { timeout: 15000 });
await sleep(900);
await shot('landing-hero');
await page.evaluate(() => document.querySelector('#hierarchy').scrollIntoView());
await sleep(1600);
await shot('landing-hierarchy');
await page.evaluate(() => { document.querySelector('#boundaries').scrollIntoView(); window.scrollBy(0, -40); });
await sleep(1600);
await shot('landing-boundaries');

// ---------------- sign in
await page.goto(BASE + '/console/signin');
await page.getByText('Alice', { exact: true }).waitFor();
await sleep(400);
await shot('signin');
await page.getByText('Alice', { exact: true }).click();
await page.waitForURL('**/console');
await page.getByText('Welcome back').waitFor();
await sleep(1500);
await shot('console-dashboard');

// ---------------- KMS
await page.goto(BASE + '/console/kms/keys');
await page.getByText('alias/patient-records').waitFor();
await sleep(600);
await shot('kms-keys');
await page.getByText('alias/patient-records').click();
await page.getByText('General configuration').waitFor();
await sleep(800);
await shot('kms-key-hierarchy', { fullPage: true });

// ---------------- Vault: upload with inspector
await page.setViewportSize({ width: 1440, height: 1250 });
await page.goto(BASE + '/console/vault/buckets/acme-patient-records');
await page.getByRole('button', { name: 'Upload' }).waitFor();
await sleep(500);
await shot('vault-objects');
await page.getByRole('button', { name: 'Upload' }).click();
await page.getByRole('button', { name: 'Encrypt and upload' }).click();
await page.getByRole('button', { name: 'Done' }).waitFor({ timeout: 20000 });
await sleep(900);
await shot('inspector-upload');
await page.getByRole('button', { name: 'See what the server stored' }).click();
await page.getByText('This is everything the storage server holds').waitFor();
await sleep(900);
await shot('vault-raw-view');
await page.keyboard.press('Escape');
await page.setViewportSize({ width: 1440, height: 900 });

// ---------------- Lab
await page.goto(BASE + '/console/lab');
await page.getByRole('button', { name: 'Run attack' }).first().waitFor();
const buttons = page.getByRole('button', { name: 'Run attack' });
for (let i = 0; i < 5; i++) {
  await buttons.first().click();
  await sleep(2600);
}
await page.waitForFunction(() => document.querySelectorAll('.lab-verdict').length >= 5, null, { timeout: 30000 });
await sleep(500);
await shot('lab', { fullPage: true });
const cards = page.locator('.lab-log');
for (let i = 0; i < 5; i++) {
  const card = cards.nth(i).locator('xpath=ancestor::*[contains(@class,"awsui_root") and .//h2][1]');
  await card.screenshot({ path: `${OUT}/lab-${i + 1}.png` });
  console.log('saved lab', i + 1);
}

// ---------------- Trade-offs
await page.goto(BASE + '/console/tradeoffs');
let bench = null;
page.on('console', (m) => { if (m.text().startsWith('[stratus-bench]')) bench = m.text().slice('[stratus-bench] '.length); });
await page.getByRole('button', { name: 'Run benchmarks' }).click();
await page.getByRole('button', { name: 'Run again' }).waitFor({ timeout: 90000 });
await sleep(1200);
await shot('tradeoffs', { fullPage: true });
if (bench) { writeFileSync(`${OUT}/bench.json`, JSON.stringify(JSON.parse(bench), null, 2)); console.log('saved bench.json'); }

// ---------------- Activity + walkthrough + dark mode
await page.goto(BASE + '/console/activity');
await page.getByText('GenerateDataKey').first().waitFor();
await sleep(600);
await shot('activity');

await page.goto(BASE + '/console/kms/keys');
await page.getByRole('button', { name: 'Walkthrough' }).click();
await page.getByRole('button', { name: 'Start tutorial' }).click();
await sleep(1200);
await shot('walkthrough');

await page.evaluate(() => localStorage.setItem('stratus.theme', 'dark'));
await page.goto(BASE + '/console');
await page.getByText('Welcome back').waitFor();
await sleep(1500);
await shot('console-dark');
await page.evaluate(() => localStorage.setItem('stratus.theme', 'light'));

await browser.close();
