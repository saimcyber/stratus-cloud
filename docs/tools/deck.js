// Stratus Cloud presentation deck (pptxgenjs, structured: theme + layouts + sections).
const path = require('path');
const pptxgen = require('pptxgenjs');
const React = require('react');
const ReactDOMServer = require('react-dom/server');
const sharp = require('sharp');
const fa = require('react-icons/fa');
const JSZip = require('jszip');

// pptxgenjs cannot set theme colours, so write the colour scheme into ppt/theme/*.xml after saving.
async function applyTheme(file, theme) {
  const fs = require('fs');
  const zip = await JSZip.loadAsync(fs.readFileSync(file), { createFolders: false });
  const esc = (t) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  const order = ['dk1', 'lt1', 'dk2', 'lt2', 'accent1', 'accent2', 'accent3', 'accent4', 'accent5', 'accent6', 'hlink', 'folHlink'];
  const scheme = `<a:clrScheme name="${esc(theme.name)}">` +
    order.map((k) => `<a:${k}><a:srgbClr val="${theme.colors[k]}"/></a:${k}>`).join('') + '</a:clrScheme>';
  for (const name of Object.keys(zip.files).filter((n) => /^ppt\/theme\/theme\d+\.xml$/.test(n))) {
    let xml = await zip.file(name).async('string');
    xml = xml.replace(/<a:clrScheme[\s\S]*?<\/a:clrScheme>/, scheme)
             .replace(/(<a:theme [^>]*name=")[^"]*"/, `$1${esc(theme.name)}"`)
             .replace(/(<a:fontScheme name=")[^"]*"/, `$1${esc(theme.name)}"`);
    zip.file(name, xml);
  }
  // Re-pack without folder entries, which some cloud viewers reject.
  const out = new JSZip();
  for (const [n, f] of Object.entries(zip.files)) if (!f.dir) out.file(n, await f.async('uint8array'), { createFolders: false });
  fs.writeFileSync(file, await out.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }));
}

const ROOT = process.argv[2];
const OUT = path.join(ROOT, 'docs', 'Stratus-Presentation.pptx');
const IMG = (n) => path.join(ROOT, 'docs', 'img', n);
// Real numbers captured from the Trade-offs page by docs/tools/capture.mjs
const BENCH = JSON.parse(require('fs').readFileSync(IMG('bench.json'), 'utf8'));
const r1 = (x) => Math.round(x * 10) / 10;
const RSA_X = BENCH.wrap[1].rsa / BENCH.wrap[1].aes;

const HEX = {
  ink: '0F1B2A', ink2: '16243A', paper: 'F6F3EC', amber: 'FF9900', amberD: 'B85F00',
  slate: '5B6472', green: '1F8A65', red: 'C2412D', line: 'DDD5C4', white: 'FFFFFF',
};
const THEME = {
  name: 'Stratus',
  headFontFace: 'Georgia',
  bodyFontFace: 'Calibri',
  colors: {
    dk1: HEX.ink, lt1: HEX.white, dk2: HEX.ink2, lt2: HEX.paper,
    accent1: HEX.amber, accent2: HEX.amberD, accent3: HEX.slate, accent4: HEX.green, accent5: HEX.red, accent6: HEX.line,
    hlink: '0972D3', folHlink: '5B6472',
  },
};

async function icon(Comp, color, size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: '#' + color, size: String(size) }));
  const buf = await sharp(Buffer.from(svg)).png().toBuffer();
  return 'image/png;base64,' + buf.toString('base64');
}

(async () => {
  const pres = new pptxgen();
  pres.layout = 'LAYOUT_WIDE'; // 13.333 x 7.5
  pres.title = 'Stratus Cloud: Envelope Encryption for Cloud Storage';
  pres.author = 'Saim Zaib, Abdullah Sajid, Muhammad Amish';
  pres.company = 'FAST NUCES Islamabad';
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  const C = pres.SchemeColor;
  const W = 13.333;

  // ---------------------------------------------------------------- layouts
  pres.defineSlideMaster({
    title: 'DARK_TITLE',
    background: { color: C.text1 },
    objects: [
      { placeholder: { options: { name: 'title', type: 'title', x: 0.7, y: 2.0, w: 7.3, h: 2.2, fontSize: 44, color: C.background1, valign: 'top', align: 'left', margin: 0 }, text: '' } },
      { placeholder: { options: { name: 'body', type: 'body', x: 0.7, y: 4.5, w: 6.8, h: 0.9, fontSize: 18, color: C.background2, valign: 'top', align: 'left', margin: 0 }, text: '' } },
    ],
  });
  pres.defineSlideMaster({
    title: 'DARK_SECTION',
    background: { color: C.text1 },
    objects: [
      { placeholder: { options: { name: 'title', type: 'title', x: 0.7, y: 2.3, w: 11.9, h: 1.6, fontSize: 54, color: C.background1, valign: 'bottom', align: 'left', margin: 0 }, text: '' } },
      { placeholder: { options: { name: 'body', type: 'body', x: 0.7, y: 4.1, w: 11.9, h: 0.8, fontSize: 20, color: C.background2, valign: 'top', align: 'left', margin: 0 }, text: '' } },
    ],
  });
  pres.defineSlideMaster({
    title: 'CONTENT',
    background: { color: C.background1 },
    margin: [0.5, 0.6, 0.6, 0.6],
    objects: [
      { placeholder: { options: { name: 'title', type: 'title', x: 0.6, y: 0.62, w: 12.1, h: 0.85, fontSize: 32, color: C.text1, valign: 'top', align: 'left', margin: 0 }, text: '' } },
      { text: { text: 'Stratus Cloud · Envelope encryption for cloud storage', options: { x: 0.6, y: 7.02, w: 7, h: 0.3, fontSize: 10, color: C.accent3, margin: 0 } } },
    ],
    slideNumber: { x: 12.33, y: 7.02, w: 0.4, h: 0.3, fontSize: 10, color: C.accent3, align: 'right' },
  });

  // ---------------------------------------------------------------- helpers
  const kicker = (s, n, label, dark = false) =>
    s.addText(`${n}  ·  ${label.toUpperCase()}`, {
      x: 0.6, y: 0.3, w: 8, h: 0.3, fontSize: 11, bold: true, charSpacing: 3, color: dark ? C.accent1 : C.accent2,
      margin: 0, isTextBox: true, objectName: 'kicker',
    });
  const card = (s, x, y, w, h, name, fill = C.background2) =>
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: fill }, line: { color: C.accent6, width: 0.75 }, objectName: name });
  const txt = (s, text, o) => s.addText(text, { margin: 0, isTextBox: true, valign: 'top', ...o });
  const shadow = () => ({ type: 'outer', color: '0F1B2A', blur: 8, offset: 2, angle: 90, opacity: 0.18 });

  const strata = (s, x, y, labels, dark) => {
    labels.forEach(([a, b], i) => {
      const ox = x + i * 0.45;
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
        x: ox, y: y + i * 0.78, w: 4.6 - i * 0.45, h: 0.62, rectRadius: 0.1,
        fill: { color: i === 0 ? C.accent1 : dark ? C.text2 : C.background2 },
        line: { color: i === 0 ? C.accent1 : dark ? '33445C' : C.accent6, width: 0.75 }, objectName: `stratum-${i + 1}`,
      });
      txt(s, [
        { text: a, options: { bold: true, color: i === 0 ? C.text1 : dark ? C.background1 : C.text1 } },
        { text: '   ' + b, options: { color: i === 0 ? C.text1 : dark ? 'AEB6C2' : C.accent3, fontSize: 12 } },
      ], { x: ox + 0.2, y: y + i * 0.78, w: 4.2 - i * 0.45, h: 0.62, fontSize: 15, valign: 'middle' });
    });
  };

  const icons = {
    db: await icon(fa.FaDatabase, HEX.amber), users: await icon(fa.FaUsers, HEX.amber), spy: await icon(fa.FaUserSecret, HEX.amber),
    laptop: await icon(fa.FaLaptop, HEX.ink), key: await icon(fa.FaKey, HEX.ink), box: await icon(fa.FaArchive, HEX.ink),
    check: await icon(fa.FaCheck, HEX.white), times: await icon(fa.FaTimes, HEX.white),
  };

  // ================================================================= 1. Title
  pres.addSection({ title: 'Opening' });
  let s = pres.addSlide({ masterName: 'DARK_TITLE', sectionTitle: 'Opening' });
  txt(s, 'CS-3002 INFORMATION SECURITY  ·  TERM PROJECT', { x: 0.7, y: 1.35, w: 8, h: 0.35, fontSize: 12, bold: true, charSpacing: 3, color: C.accent1, objectName: 'kicker' });
  s.addText([{ text: 'Envelope encryption', options: { breakLine: true } }, { text: 'for ' }, { text: 'cloud storage', options: { italic: true, color: C.accent1 } }], { placeholder: 'title' });
  s.addText('Stratus Cloud: a multi-tenant key management service and an untrusted object store', { placeholder: 'body' });
  strata(s, 8.1, 2.15, [['Root KEK', 'KMS only'], ['Customer managed key', 'per tenant'], ['Data key', 'per file']], true);
  txt(s, 'Saim Zaib  ·  Abdullah Sajid  ·  Muhammad Amish', { x: 0.7, y: 6.3, w: 7.5, h: 0.35, fontSize: 14, color: C.background1, objectName: 'team' });
  txt(s, 'Instructor: Dr. Hina Binte Haq  ·  FAST NUCES Islamabad', { x: 0.7, y: 6.65, w: 7.5, h: 0.35, fontSize: 12, color: 'AEB6C2', objectName: 'instructor' });
  s.addNotes('Open with the one-line idea: the cloud should store data it can never read. Stratus is our working model of how a cloud KMS does that, with three keys in three places.');

  // ================================================================= 2. Problem
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Opening' });
  kicker(s, '01', 'The problem');
  s.addText('Whoever holds the key holds the data', { placeholder: 'title' });
  [
    [icons.db, 'Storage leaks', 'A leaked bucket or database dump should reveal nothing.'],
    [icons.users, 'Clouds are shared', 'Thousands of tenants on one service must never see each other.'],
    [icons.spy, 'Admins can look', 'Operators and insiders should not be able to read customer files.'],
  ].forEach(([ic, h, b], i) => {
    const x = 0.6 + i * 4.13;
    card(s, x, 1.95, 3.85, 3.55, `problem-${i + 1}`);
    s.addShape(pres.shapes.OVAL, { x: x + 0.35, y: 2.3, w: 0.9, h: 0.9, fill: { color: C.text1 }, line: { color: C.text1 }, objectName: `problem-icon-bg-${i + 1}` });
    s.addImage({ data: ic, x: x + 0.58, y: 2.53, w: 0.44, h: 0.44, altText: h, objectName: `problem-icon-${i + 1}` });
    txt(s, h, { x: x + 0.35, y: 3.45, w: 3.2, h: 0.5, fontSize: 21, bold: true, color: C.text1, fontFace: 'Georgia' });
    txt(s, b, { x: x + 0.35, y: 4.05, w: 3.2, h: 1.2, fontSize: 16, color: C.accent3 });
  });
  txt(s, [{ text: 'Goal  ', options: { bold: true, color: C.accent2 } }, { text: 'The cloud stores your data but can never read it, and your keys stay under policy you control.' }],
    { x: 0.6, y: 5.95, w: 12.1, h: 0.5, fontSize: 18, color: C.text1, objectName: 'goal' });
  s.addNotes('Three realities of cloud storage: breaches, multi-tenancy, insiders. Encryption only helps if the key is somewhere the attacker is not.');

  // ================================================================= 3. The idea
  pres.addSection({ title: 'Design' });
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Design' });
  kicker(s, '02', 'Envelope encryption');
  s.addText('Encrypt the data, then encrypt the key', { placeholder: 'title' });
  const rows = [
    ['Data key (DEK)', 'encrypts', 'your file', 'AES-256-GCM, in the browser'],
    ['Customer key (CMK)', 'wraps', 'the data key', 'AES Key Wrap or RSA-2048-OAEP'],
    ['Root KEK', 'seals', 'the customer key', 'AES Key Wrap, inside the KMS'],
  ];
  rows.forEach(([k, verb, what, how], i) => {
    const y = 2.0 + i * 1.45;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.6, y, w: 3.4, h: 1.05, rectRadius: 0.1, fill: { color: i === 2 ? C.accent1 : C.text1 }, line: { color: i === 2 ? C.accent1 : C.text1 }, objectName: `idea-key-${i + 1}` });
    txt(s, k, { x: 0.8, y, w: 3.0, h: 1.05, fontSize: 18, bold: true, valign: 'middle', color: i === 2 ? C.text1 : C.background1 });
    s.addShape(pres.shapes.RIGHT_ARROW, { x: 4.2, y: y + 0.33, w: 1.0, h: 0.4, fill: { color: C.accent6 }, line: { color: C.accent6 }, objectName: `idea-arrow-${i + 1}` });
    txt(s, verb, { x: 4.0, y: y - 0.12, w: 1.4, h: 0.35, fontSize: 13, italic: true, color: C.accent3, align: 'center' });
    card(s, 5.4, y, 3.1, 1.05, `idea-what-${i + 1}`);
    txt(s, what, { x: 5.6, y, w: 2.8, h: 1.05, fontSize: 18, bold: true, valign: 'middle', color: C.text1 });
    txt(s, how, { x: 8.8, y, w: 3.9, h: 1.05, fontSize: 16, valign: 'middle', color: C.accent3 });
  });
  txt(s, 'Only the small wrapped key travels to the KMS. The file never does.', { x: 0.6, y: 6.35, w: 12.1, h: 0.45, fontSize: 18, italic: true, color: C.accent2, fontFace: 'Georgia', objectName: 'idea-tagline' });
  s.addNotes('Three keys, three jobs. A fresh data key per file; the tenant key wraps it; the root key seals the tenant key. Rotation and revocation happen on the small keys, never on the data.');

  // ================================================================= 4. Architecture
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Design' });
  kicker(s, '03', 'Architecture');
  s.addText('Three parties, each told only what it needs', { placeholder: 'title' });
  const lanes = [
    [icons.laptop, 'Your browser', 'Trusted client', ['the file', 'the data key, for milliseconds'], []],
    [icons.key, 'Stratus KMS', 'Trusted for keys', ['32-byte keys', 'object labels', 'access lists'], ['your file']],
    [icons.box, 'Stratus Vault', 'Untrusted storage', ['ciphertext', 'wrapped keys'], ['your file', 'any usable key']],
  ];
  lanes.forEach(([ic, name, role, sees, never], i) => {
    const x = 0.6 + i * 4.13;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.9, w: 3.85, h: 3.9, rectRadius: 0.08, fill: { color: i === 2 ? C.background1 : C.background2 }, line: { color: i === 2 ? C.accent1 : C.accent6, width: i === 2 ? 1.25 : 0.75, dashType: i === 2 ? 'dash' : 'solid' }, objectName: `lane-${i + 1}` });
    s.addImage({ data: ic, x: x + 0.35, y: 2.2, w: 0.42, h: 0.42, altText: name, objectName: `lane-icon-${i + 1}` });
    txt(s, name, { x: x + 0.95, y: 2.15, w: 2.8, h: 0.4, fontSize: 19, bold: true, color: C.text1 });
    txt(s, role, { x: x + 0.95, y: 2.55, w: 2.8, h: 0.35, fontSize: 13, color: i === 2 ? C.accent2 : C.accent3 });
    const items = [
      ...sees.map((t) => ({ text: 'sees  ', options: { color: C.accent4, bold: true, fontSize: 13 } })).flatMap((lab, k) => [lab, { text: sees[k], options: { breakLine: true } }]),
      ...never.map((t) => [{ text: 'never  ', options: { color: C.accent5, bold: true, fontSize: 13 } }, { text: t, options: { breakLine: true, strike: 'sngStrike', color: C.accent3 } }]).flat(),
    ];
    txt(s, items, { x: x + 0.35, y: 3.2, w: 3.3, h: 2.4, fontSize: 16, color: C.text1, paraSpaceAfter: 8 });
  });
  txt(s, [{ text: 'Enforced by deployment  ', options: { bold: true, color: C.accent2 } }, { text: 'two services · two databases with separate roles · secrets split between them · the Vault only gets a public verification key' }],
    { x: 0.6, y: 6.15, w: 12.1, h: 0.6, fontSize: 16, color: C.text1, objectName: 'arch-callout' });
  s.addNotes('The boundary is real, not drawn: the Vault has no KMS credentials, no signing key, and never calls the KMS. Its whole database could leak and nothing is readable.');

  // ================================================================= 5. Upload flow
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Design' });
  kicker(s, '04', 'Protocol');
  s.addText('One upload, step by step', { placeholder: 'title' });
  s.addImage({ path: IMG('inspector-upload.png'), x: 0.6, y: 1.65, w: 5.9, h: 5.12, altText: 'Envelope Inspector showing the five upload steps', objectName: 'inspector', shadow: shadow() });
  [
    ['Ask the KMS for a data key', 'Sends only {tenant, bucket, object}'],
    ['Get the key and its wrapped copy', 'Wrapped with AES Key Wrap, HMAC-bound to the labels'],
    ['Wipe the raw key bytes', 'Imported as a non-extractable CryptoKey, buffer filled with 00'],
    ['Encrypt locally', 'AES-256-GCM, random 96-bit IV, labels as AAD'],
    ['Store ciphertext + wrapped key', 'The Vault never sees anything usable'],
  ].forEach(([h, b], i) => {
    const y = 1.75 + i * 1.0;
    s.addShape(pres.shapes.OVAL, { x: 7.0, y, w: 0.55, h: 0.55, fill: { color: i === 2 ? C.accent1 : C.text1 }, line: { color: i === 2 ? C.accent1 : C.text1 }, objectName: `step-dot-${i + 1}` });
    txt(s, String(i + 1), { x: 7.0, y, w: 0.55, h: 0.55, fontSize: 16, bold: true, align: 'center', valign: 'middle', color: i === 2 ? C.text1 : C.background1 });
    txt(s, h, { x: 7.8, y: y - 0.03, w: 4.9, h: 0.4, fontSize: 18, bold: true, color: C.text1 });
    txt(s, b, { x: 7.8, y: y + 0.36, w: 4.9, h: 0.5, fontSize: 14, color: C.accent3 });
  });
  s.addNotes('Walk the Inspector screenshot: request, receive, wipe, encrypt, store. Point at the 00 grid: the raw data key is wiped before encryption even starts.');

  // ================================================================= 6. Crypto choices
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Design' });
  kicker(s, '05', 'Cryptography');
  s.addText('Standard primitives, standard libraries', { placeholder: 'title' });
  [
    ['AES-256-GCM', 'File encryption', 'Authenticated; any change breaks the tag', 'Web Crypto API'],
    ['AES Key Wrap', 'Wraps data keys and seals CMKs', 'RFC 3394, checked against RFC test vectors', 'pyca/cryptography'],
    ['RSA-2048-OAEP', 'Alternative key wrapping', 'SHA-256 OAEP, never PKCS#1 v1.5', 'pyca/cryptography'],
    ['HMAC-SHA256', 'Binds wrapped key to its labels', 'Fixes AES-KW having no associated data', 'pyca/cryptography'],
    ['HKDF-SHA256', 'Separate keys per purpose', 'One CMK version, independent wrap and MAC keys', 'pyca/cryptography'],
    ['Ed25519 + scrypt', 'Sessions and passwords', 'KMS signs, Vault can only verify', 'PyJWT, hashlib'],
  ].forEach(([name, use, why, lib], i) => {
    const x = 0.6 + (i % 3) * 4.13;
    const y = 1.85 + Math.floor(i / 3) * 2.45;
    card(s, x, y, 3.85, 2.2, `crypto-${i + 1}`);
    txt(s, name, { x: x + 0.3, y: y + 0.25, w: 3.3, h: 0.5, fontSize: 22, bold: true, color: C.text1, fontFace: 'Georgia' });
    txt(s, use, { x: x + 0.3, y: y + 0.8, w: 3.3, h: 0.35, fontSize: 15, bold: true, color: C.accent2 });
    txt(s, why, { x: x + 0.3, y: y + 1.15, w: 3.3, h: 0.6, fontSize: 14, color: C.accent3 });
    txt(s, lib, { x: x + 0.3, y: y + 1.75, w: 3.3, h: 0.3, fontSize: 12, italic: true, color: C.accent3 });
  });
  s.addNotes('No custom crypto. The one design decision worth defending: AES Key Wrap has no AAD, so we HMAC the wrapped key together with its labels. That is what stops key-swap attacks.');

  // ================================================================= 7. Lifecycle
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Design' });
  kicker(s, '06', 'Key lifecycle');
  s.addText('Rotate, revoke and shred without touching data', { placeholder: 'title' });
  const life = [
    ['Generate', 'OS randomness; a fresh data key per file'],
    ['Rotate', 'New CMK version; old ones decrypt only'],
    ['Re-wrap', 'KMS swaps the wrapped key; file hash unchanged'],
    ['Revoke', 'Remove a user or disable the key, instantly'],
    ['Shred', 'Delete the CMK; every copy is unreadable'],
  ];
  s.addShape(pres.shapes.LINE, { x: 1.2, y: 2.62, w: 10.9, h: 0, line: { color: C.accent6, width: 2 }, objectName: 'timeline' });
  life.forEach(([h, b], i) => {
    const x = 0.6 + i * 2.45;
    s.addShape(pres.shapes.OVAL, { x: x + 0.38, y: 2.3, w: 0.64, h: 0.64, fill: { color: i === 4 ? C.accent5 : i === 1 ? C.accent1 : C.text1 }, line: { color: C.background1, width: 3 }, objectName: `life-dot-${i + 1}` });
    txt(s, h, { x, y: 3.15, w: 2.3, h: 0.45, fontSize: 20, bold: true, color: C.text1, fontFace: 'Georgia' });
    txt(s, b, { x, y: 3.62, w: 2.2, h: 1.0, fontSize: 14, color: C.accent3 });
  });
  card(s, 0.6, 5.05, 12.1, 1.55, 'zeroize-card');
  txt(s, [
    { text: 'Zeroization  ', options: { bold: true, color: C.accent2 } },
    { text: 'KMS: every key in a bytearray, wiped with memset in a finally block. Browser: key imported non-extractable, raw buffer filled with zeros. ', options: { breakLine: false } },
    { text: 'Best-effort in managed runtimes, and we say so in the threat model.', options: { italic: true } },
  ], { x: 0.9, y: 5.25, w: 11.5, h: 1.2, fontSize: 16, color: C.text1, valign: 'middle' });
  s.addNotes('Rotation never breaks old files because the wrapped key names its version. Re-wrap moves about 300 bytes per object. Deletion destroys key material, so even old backups become useless.');

  // ================================================================= 8. Concurrency
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Design' });
  kicker(s, '07', 'Multi-tenancy and concurrency');
  s.addText('Under load, with attackers in the queue', { placeholder: 'title' });
  [
    ['100 / 100', 'data-key round trips correct on 24 threads'],
    ['0 / 25', 'cross-tenant attempts succeeded'],
    ['v2 · v3 · v4', 'unique versions from rotations mid-traffic'],
  ].forEach(([big, lab], i) => {
    const y = 1.85 + i * 1.6;
    txt(s, big, { x: 0.6, y, w: 5.2, h: 0.95, fontSize: 54, color: i === 1 ? C.accent2 : C.text1, fontFace: 'Georgia', objectName: `stat-${i + 1}` });
    txt(s, lab, { x: 0.6, y: y + 0.9, w: 5.2, h: 0.45, fontSize: 15, color: C.accent3 });
  });
  card(s, 6.4, 1.85, 6.3, 4.75, 'mechanisms');
  txt(s, 'How', { x: 6.75, y: 2.1, w: 5.6, h: 0.45, fontSize: 20, bold: true, color: C.text1, fontFace: 'Georgia' });
  txt(s, [
    { text: 'Every query scoped to the tenant in the signed token', options: { bullet: true, breakLine: true } },
    { text: 'Per-key access lists: users encrypt, admins manage', options: { bullet: true, breakLine: true } },
    { text: 'Rotation: row lock + unique version constraint', options: { bullet: true, breakLine: true } },
    { text: 'Rate limit, plus lockout after repeated denials', options: { bullet: true, breakLine: true } },
    { text: 'Every call audited, including refusals', options: { bullet: true } },
  ], { x: 6.75, y: 2.7, w: 5.7, h: 3.6, fontSize: 16, color: C.text1, paraSpaceAfter: 10 });
  s.addNotes('The load test mixes 100 legitimate round trips, 25 attacks and 3 rotations. It found a real bug for us: a connection-pool deadlock. Every assertion now passes.');

  // ================================================================= 9. Section: break it
  pres.addSection({ title: 'Security evaluation' });
  s = pres.addSlide({ masterName: 'DARK_SECTION', sectionTitle: 'Security evaluation' });
  kicker(s, '08', 'Security evaluation', true);
  s.addText([{ text: 'Now try to ' }, { text: 'break it', options: { italic: true, color: C.accent1 } }], { placeholder: 'title' });
  s.addText('A threat model, then five live attacks against the running system', { placeholder: 'body' });
  s.addNotes('Switch from how it works to how it holds up.');

  // ================================================================= 10. Threat model
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Security evaluation' });
  kicker(s, '09', 'Threat model');
  s.addText('Who we defend against', { placeholder: 'title' });
  [['Browser', 'trusted', C.accent4], ['KMS host', 'trusted', C.accent4], ['Vault', 'untrusted', C.accent5], ['Other tenants', 'malicious', C.accent5], ['Network', 'untrusted', C.accent5]].forEach(([a, b, col], i) => {
    const x = 0.6 + i * 2.45;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.75, w: 2.25, h: 0.62, rectRadius: 0.3, fill: { color: C.background2 }, line: { color: col, width: 1.25 }, objectName: `assume-${i + 1}` });
    txt(s, [{ text: a + '  ', options: { bold: true, color: C.text1 } }, { text: b, options: { color: col } }], { x, y: 1.75, w: 2.25, h: 0.62, fontSize: 13, align: 'center', valign: 'middle' });
  });
  const hdr = (t) => ({ text: t, options: { bold: true, color: C.background1, fill: { color: C.text1 } } });
  const row = (a, b, c) => [{ text: a, options: { bold: true } }, { text: b }, { text: c, options: { color: C.accent4, bold: true } }];
  s.addTable([
    [hdr('Adversary'), hdr('Attack'), hdr('Stopped by')],
    row('Curious storage admin', 'Reads every stored file', 'Client-side AES-GCM'),
    row('Malicious storage', 'Flips bits in a file', 'GCM authentication tag'),
    row('Malicious storage', 'Swaps keys between files', 'Context HMAC + AAD'),
    row('Another tenant', 'Uses stolen wrapped keys', 'Tenant check + key ACL'),
    row('Brute force', 'Floods the KMS', 'Rate limit + lockout'),
    row('Old backups', 'Reads deleted data', 'Crypto-shredding'),
  ], { x: 0.6, y: 2.75, w: 12.1, colW: [3.4, 4.6, 4.1], fontSize: 15, color: C.text1, border: { type: 'solid', color: HEX.line, pt: 0.75 }, rowH: 0.5, margin: [0.06, 0.12, 0.06, 0.12], objectName: 'threat-table' });
  s.addNotes('Trust assumptions first. The Vault is untrusted by design. Out of scope: a compromised laptop or KMS host. A real KMS uses an HSM for the latter.');

  // ================================================================= 11. Attack lab
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Security evaluation' });
  kicker(s, '10', 'Security lab');
  s.addText('Five attacks, five refusals', { placeholder: 'title' });
  [
    ['Dump the storage DB', '0 keyword hits, only ciphertext'],
    ['Cross-tenant key theft', '403, 403, 403, then 429 lockout'],
    ['Flip one ciphertext bit', 'AES-GCM tag mismatch'],
    ['Swap keys between files', 'InvalidCiphertext + tag mismatch'],
    ['Read after key deletion', 'Key destroyed: unrecoverable'],
  ].forEach(([a, r], i) => {
    const y = 1.8 + i * 1.0;
    txt(s, String(i + 1).padStart(2, '0'), { x: 0.6, y, w: 0.6, h: 0.45, fontSize: 18, bold: true, color: C.accent2 });
    txt(s, a, { x: 1.2, y, w: 4.6, h: 0.42, fontSize: 18, bold: true, color: C.text1 });
    txt(s, r, { x: 1.2, y: y + 0.42, w: 4.6, h: 0.4, fontSize: 14, color: C.accent5 });
  });
  s.addImage({ path: IMG('lab-2.png'), x: 6.25, y: 1.8, w: 6.45, h: 6.45 * 642 / 1920, altText: 'Lab 2 output: cross-tenant attempts denied and throttled', objectName: 'lab2', shadow: shadow() });
  s.addImage({ path: IMG('lab-3.png'), x: 6.25, y: 4.25, w: 6.45, h: 6.45 * 483 / 1920, altText: 'Lab 3 output: bit flip detected by AES-GCM', objectName: 'lab3', shadow: shadow() });
  s.addNotes('Every card runs against the deployed services during the demo; all five were verified on the live site. Lab 2: Mallory from Globex is denied at the Vault, denied at the KMS, denied again with forged labels, then throttled.');

  // ================================================================= 12. Trade-offs
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Security evaluation' });
  kicker(s, '11', 'Security vs. usability');
  s.addText('Security has a price, so we measured it', { placeholder: 'title' });
  const axis = { catAxisLabelColor: HEX.slate, valAxisLabelColor: HEX.slate, catAxisLabelFontSize: 12, valAxisLabelFontSize: 11, catAxisLabelFontFace: '+mn-lt', valAxisLabelFontFace: '+mn-lt',
    valGridLine: { color: 'E6E0D3', size: 0.75 }, catGridLine: { style: 'none' }, titleFontFace: '+mn-lt', titleFontSize: 15, titleColor: HEX.ink,
    legendFontFace: '+mn-lt', legendFontSize: 12, legendColor: HEX.slate, showLegend: true, legendPos: 'b', valAxisTitleFontFace: '+mn-lt' };
  s.addChart(pres.charts.BAR, [
    { name: 'AES Key Wrap', labels: ['GenerateDataKey', 'Decrypt'], values: BENCH.wrap.map((w) => r1(w.aes)) },
    { name: 'RSA-2048-OAEP', labels: ['GenerateDataKey', 'Decrypt'], values: BENCH.wrap.map((w) => r1(w.rsa)) },
  ], { x: 0.6, y: 1.75, w: 5.9, h: 4.3, barDir: 'col', barGapWidthPct: 60, chartColors: [HEX.ink, HEX.amber], showTitle: true, title: 'KMS server time (ms)',
    showValue: true, dataLabelPosition: 'outEnd', dataLabelFontSize: 12, dataLabelColor: HEX.ink, dataLabelFontFace: '+mn-lt', dataLabelFormatCode: '0.0', ...axis, objectName: 'chart-wrap' });
  s.addChart(pres.charts.LINE, [
    { name: 'Re-wrap the data key', labels: BENCH.gcm.map((g) => g.size), values: BENCH.gcm.map(() => r1(BENCH.rewrapMs)) },
    { name: 'Re-encrypt the file (crypto only)', labels: BENCH.gcm.map((g) => g.size), values: BENCH.gcm.map((g) => r1(g.enc + g.dec)) },
  ], { x: 6.8, y: 1.75, w: 5.9, h: 4.3, chartColors: [HEX.ink, HEX.amber], lineSize: 3, lineDataSymbol: 'circle', lineDataSymbolSize: 7, showTitle: true, title: 'Rotating one object (ms)', ...axis, objectName: 'chart-rotation' });
  txt(s, [
    { text: `RSA unwrap costs about ${RSA_X.toFixed(1)}× more. `, options: { bold: true } },
    { text: 'Re-wrapping is flat; re-encrypting grows with file size and also needs a full download and re-upload.' },
  ], { x: 0.6, y: 6.25, w: 12.1, h: 0.55, fontSize: 15, color: C.text1, objectName: 'tradeoff-caption' });
  s.addNotes(`Measured live from the browser on the Trade-offs page, one local run on Postgres. On the free hosting the round trip is slower, but the ratios hold. Data-key round trip about ${Math.round(BENCH.dataKeyMs)} ms; AES-GCM at about ${Math.round(BENCH.gcm.at(-1).mbps)} MB/s in the browser; 16 bytes of ciphertext overhead.`);

  // ================================================================= 13. Usability
  pres.addSection({ title: 'Product' });
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Product' });
  kicker(s, '12', 'Usability');
  s.addText('Built so a first-time user can follow it', { placeholder: 'title' });
  s.addImage({ path: IMG('walkthrough.png'), x: 0.6, y: 1.75, w: 6.9, h: 6.9 / 1.6, altText: 'Guided walkthrough with hotspots', objectName: 'shot-walkthrough', shadow: shadow() });
  [
    ['Guided walkthrough', 'Tutorial panel with hotspots on the real controls'],
    ['Envelope Inspector', 'Animates every upload and download across the three parties'],
    ['Raw view', 'Shows exactly what the storage server holds'],
    ['Info panels and glossary', 'Plain-language help for DEK, CMK, KEK and context'],
  ].forEach(([h, b], i) => {
    const y = 1.8 + i * 1.08;
    txt(s, h, { x: 7.9, y, w: 4.8, h: 0.42, fontSize: 18, bold: true, color: C.text1 });
    txt(s, b, { x: 7.9, y: y + 0.42, w: 4.8, h: 0.55, fontSize: 14, color: C.accent3 });
  });
  s.addNotes('The course asks for onboarding. The walkthrough points at real controls; the Inspector makes invisible crypto visible.');

  // ================================================================= 14. Hurdles + limits
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Product' });
  kicker(s, '13', 'Lessons');
  s.addText('What fought back, and what we would do next', { placeholder: 'title' });
  [
    ['AES-KW has no AAD', 'A wrapped key could be replayed on another file. Fixed with an HMAC over key + labels.'],
    ['Deadlock under load', 'Audit logging opened a second DB connection per request. The load test found it.'],
    ['Rotation race', 'Parallel rotations reported the wrong version. Now each returns the one it minted.'],
  ].forEach(([h, b], i) => {
    const x = 0.6 + i * 4.13;
    card(s, x, 1.85, 3.85, 2.3, `hurdle-${i + 1}`);
    txt(s, h, { x: x + 0.3, y: 2.1, w: 3.3, h: 0.45, fontSize: 19, bold: true, color: C.text1, fontFace: 'Georgia' });
    txt(s, b, { x: x + 0.3, y: 2.65, w: 3.3, h: 1.35, fontSize: 15, color: C.accent3 });
  });
  txt(s, 'Next', { x: 0.6, y: 4.6, w: 3, h: 0.45, fontSize: 20, bold: true, color: C.accent2, fontFace: 'Georgia' });
  txt(s, [
    { text: 'Root KEK in an HSM instead of an environment secret', options: { bullet: true, breakLine: true } },
    { text: 'Key storage whose deletion survives database backups', options: { bullet: true, breakLine: true } },
    { text: 'Chunked streaming AEAD for files larger than 10 MB', options: { bullet: true } },
  ], { x: 0.6, y: 5.1, w: 12.1, h: 1.6, fontSize: 16, color: C.text1, paraSpaceAfter: 6 });
  s.addNotes('Be upfront about limits; they come up in peer questions. Zeroization in Python and JavaScript is best-effort, and the Root KEK is an env secret rather than an HSM.');

  // ================================================================= 15. Demo / close
  pres.addSection({ title: 'Close' });
  s = pres.addSlide({ masterName: 'DARK_SECTION', sectionTitle: 'Close' });
  kicker(s, '14', 'Live demo', true);
  s.addText([{ text: 'Let us ' }, { text: 'show you', options: { italic: true, color: C.accent1 } }], { placeholder: 'title' });
  s.addText('Upload with the Inspector  ·  rotate and re-wrap  ·  Mallory attacks  ·  crypto-shred', { placeholder: 'body' });
  txt(s, 'stratus-cloud-one.vercel.app  ·  github.com/saimcyber/stratus-cloud', { x: 0.7, y: 5.55, w: 11.9, h: 0.4, fontSize: 16, color: C.accent1, objectName: 'links' });
  txt(s, 'Questions welcome', { x: 0.7, y: 6.3, w: 6, h: 0.4, fontSize: 16, color: 'AEB6C2', objectName: 'questions' });
  s.addNotes('Live at stratus-cloud-one.vercel.app. Demo order: sign in as Alice, upload with the Inspector, open Raw view, rotate and re-wrap (hash unchanged), switch to Mallory and run Lab 2, finish with Lab 5. Warm up the free services two minutes before.');

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log('wrote', OUT);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
