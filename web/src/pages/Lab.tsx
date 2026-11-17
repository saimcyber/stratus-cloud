import { useState, type ReactNode } from 'react';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import { ApiError, kms, vault, type StoredObject } from '../lib/api';
import { b64, canonical, encryptAndUpload, hex, utf8Encoder } from '../lib/envelope';
import { errorText } from '../lib/session';
import { InfoLink, usePage } from '../console/Shell';
import Term from '../components/Term';

// ------------------------------------------------------------------------------------------ helpers
type Tone = 'attack' | 'blocked' | 'ok' | 'info';
interface Line {
  tone: Tone;
  who: string;
  text: string;
  mono?: string;
}
type Log = (l: Line) => void;

const tokens = new Map<string, Promise<{ token: string; tenant: string }>>();
function as(username: string) {
  if (!tokens.has(username)) {
    tokens.set(
      username,
      kms.demoLogin(username).then((r) => ({ token: r.token, tenant: r.user.tenant_id })),
    );
  }
  return tokens.get(username)!;
}

async function keyIdFor(token: string, alias: string) {
  const k = (await kms.keys(token)).find((x) => x.alias === alias);
  if (!k) throw new Error(`${alias} not found`);
  return k.key_id;
}

async function expectFailure(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof ApiError) return `${e.status} ${e.code}`;
    if (e instanceof DOMException) return `${e.name}: AES-GCM tag mismatch`;
    return errorText(e);
  }
  throw new Error('The attack unexpectedly succeeded');
}

async function localDecrypt(dekB64: string, iv: string, body: Uint8Array, aad: string) {
  const raw = b64.decode(dekB64);
  const key = await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['decrypt']);
  raw.fill(0);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64.decode(iv) as BufferSource, additionalData: utf8Encoder.encode(aad) },
      key,
      body as BufferSource,
    ),
  );
}

async function labUpload(name: string, text: string, keyAlias = 'alias/patient-records'): Promise<StoredObject> {
  const alice = await as('alice');
  return encryptAndUpload({
    token: alice.token,
    tenant: alice.tenant,
    bucket: 'acme-patient-records',
    objectKey: `lab/${name}`,
    data: utf8Encoder.encode(text),
    contentType: 'text/plain',
    keyId: await keyIdFor(alice.token, keyAlias),
  });
}

async function cleanup(...objs: (StoredObject | undefined)[]) {
  const alice = await as('alice');
  await Promise.all(objs.filter(Boolean).map((o) => vault.deleteObject(alice.token, 'acme-patient-records', o!.id).catch(() => {})));
}

// ------------------------------------------------------------------------------------------ attacks
interface Attack {
  id: string;
  title: string;
  threat: string;
  defence: ReactNode;
  run: (log: Log) => Promise<string>;
}

const ATTACKS: Attack[] = [
  {
    id: 'dump',
    title: 'Steal the storage database',
    threat: 'A malicious storage admin (or anyone who breaches the Vault) copies every stored row, across every tenant.',
    defence: (
      <>
        Files are encrypted in the browser before upload, and the Vault never receives a usable key: only <Term k="WRAPPED">wrapped data keys</Term> that
        need the KMS to open. The Vault has no KMS credentials and cannot mint sessions.
      </>
    ),
    run: async (log) => {
      const m = await as('mallory');
      log({ tone: 'attack', who: 'attacker', text: 'Dumping the storage database (all tenants)…' });
      const rows = await vault.dump(m.token);
      if (rows.length === 0) {
        log({ tone: 'info', who: 'lab', text: 'The Vault is empty. Upload a file first, then run this again.' });
        return 'Nothing to steal yet';
      }
      const tenants = new Set(rows.map((r) => r.tenant));
      log({ tone: 'info', who: 'attacker', text: `Got ${rows.length} objects from ${tenants.size} tenants.` });
      rows.slice(0, 3).forEach((r) =>
        log({ tone: 'info', who: 'attacker', text: `${r.tenant}/${r.bucket}/${r.object_key}`, mono: r.ciphertext_hex_preview.replace(/(.{4})/g, '$1 ').slice(0, 72) + '…' }),
      );
      const needles = ['patient', 'diagnosis', 'invoice', 'ledger', 'balance'];
      const hits = rows.filter((r) => {
        const bytes = r.ciphertext_hex_preview.match(/../g)?.map((h) => parseInt(h, 16)) ?? [];
        const text = String.fromCharCode(...bytes).toLowerCase();
        return needles.some((n) => text.includes(n));
      }).length;
      log({ tone: 'blocked', who: 'result', text: `Keyword search for ${needles.join(', ')}: ${hits} hits. The bytes are indistinguishable from random.` });
      log({ tone: 'info', who: 'attacker', text: `Found ${rows.length} wrapped data keys. Taking them to the KMS (see attack 2).` });
      return 'Attacker holds ciphertext only';
    },
  },
  {
    id: 'cross',
    title: 'Cross-tenant access and key theft',
    threat: 'Mallory, a signed-in user from Globex Finance, tries to read Acme Health data and to unwrap a stolen Acme data key.',
    defence: (
      <>
        Every Vault and KMS request is checked against the caller's tenant, and every key has its own access list. The wrapped key is bound to its{' '}
        <Term k="CONTEXT">encryption context</Term> by an HMAC, so forging the labels does not help. Repeated refusals trigger a lockout.
      </>
    ),
    run: async (log) => {
      const m = await as('mallory');
      const target = (await vault.dump(m.token)).find((r) => r.tenant === 'acme-health');
      if (!target) {
        log({ tone: 'info', who: 'lab', text: 'No Acme objects to target. Upload one as Alice or Bob first.' });
        return 'Nothing to target';
      }
      log({ tone: 'attack', who: 'mallory', text: `GET acme-patient-records objects from the Vault` });
      log({ tone: 'blocked', who: 'vault', text: await expectFailure(() => vault.objects(m.token, target.bucket)) });

      log({ tone: 'attack', who: 'mallory', text: `Decrypt the stolen wrapped key for ${target.object_key} at the KMS` });
      log({ tone: 'blocked', who: 'kms', text: await expectFailure(() => kms.decrypt(m.token, target.ciphertext_blob, target.encryption_context)) });

      log({ tone: 'attack', who: 'mallory', text: 'Same blob, context forged to say tenant=globex-finance' });
      log({
        tone: 'blocked',
        who: 'kms',
        text: await expectFailure(() => kms.decrypt(m.token, target.ciphertext_blob, { ...target.encryption_context, tenant: 'globex-finance' })),
      });

      log({ tone: 'attack', who: 'mallory', text: 'Brute force: 10 rapid retries' });
      const results = await Promise.all(
        Array.from({ length: 10 }, () => expectFailure(() => kms.decrypt(m.token, target.ciphertext_blob, target.encryption_context))),
      );
      const throttled = results.filter((r) => r.startsWith('429')).length;
      log({ tone: 'blocked', who: 'kms', text: `${results.length - throttled}× 403 AccessDenied, ${throttled}× 429 Throttling (account locked for 30s)` });
      return '0 of 13 requests succeeded';
    },
  },
  {
    id: 'flip',
    title: 'Tamper with stored ciphertext',
    threat: 'The storage server silently flips a bit in a stored file, hoping the owner decrypts corrupted or attacker-chosen data.',
    defence: (
      <>
        <Term k="GCM">AES-256-GCM</Term> is authenticated encryption. A 128-bit tag covers the ciphertext, IV and context; any change makes decryption fail loudly instead of
        returning altered data.
      </>
    ),
    run: async (log) => {
      const alice = await as('alice');
      const obj = await labUpload('tamper-test.txt', 'Dosage: 5 mg');
      try {
        log({ tone: 'info', who: 'alice', text: 'Uploaded lab/tamper-test.txt: "Dosage: 5 mg"' });
        const body = (await vault.body(alice.token, obj.envelope.encryption_context.bucket, obj.id)).data;
        const tampered = body.slice();
        tampered[8] ^= 0x01;
        log({ tone: 'attack', who: 'storage', text: 'Flip one bit of byte 8', mono: `${hex(body.subarray(0, 12))}  →  ${hex(tampered.subarray(0, 12))}` });
        const dk = (await kms.decrypt(alice.token, obj.envelope.ciphertext_blob, obj.envelope.encryption_context)).data;
        const aad = canonical(obj.envelope.encryption_context);
        log({ tone: 'blocked', who: 'browser', text: await expectFailure(() => localDecrypt(dk.plaintext, obj.envelope.iv, tampered, aad)) });
        const good = await localDecrypt(dk.plaintext, obj.envelope.iv, body, aad);
        log({ tone: 'ok', who: 'browser', text: `Untouched copy still decrypts: "${new TextDecoder().decode(good)}"` });
        return 'Tampering detected';
      } finally {
        await cleanup(obj);
      }
    },
  },
  {
    id: 'swap',
    title: 'Swap keys between objects',
    threat: 'A malicious server moves one object\'s wrapped key or ciphertext onto another object, to confuse the owner or replay old data.',
    defence: (
      <>
        The <Term k="CONTEXT">encryption context</Term> names the exact tenant, bucket and object. The KMS checks it with an HMAC before unwrapping, and the browser
        passes it as GCM additional data, so pieces of different objects never fit together.
      </>
    ),
    run: async (log) => {
      const alice = await as('alice');
      const a = await labUpload('swap-a.txt', 'Result: negative');
      const b = await labUpload('swap-b.txt', 'Result: positive');
      try {
        log({ tone: 'info', who: 'alice', text: 'Uploaded lab/swap-a.txt and lab/swap-b.txt' });
        log({ tone: 'attack', who: 'storage', text: "Serve A's wrapped key as if it belonged to B" });
        log({ tone: 'blocked', who: 'kms', text: await expectFailure(() => kms.decrypt(alice.token, a.envelope.ciphertext_blob, b.envelope.encryption_context)) });

        log({ tone: 'attack', who: 'storage', text: "Serve A's ciphertext and key under B's name" });
        const dkA = (await kms.decrypt(alice.token, a.envelope.ciphertext_blob, a.envelope.encryption_context)).data;
        const bodyA = (await vault.body(alice.token, 'acme-patient-records', a.id)).data;
        log({
          tone: 'blocked',
          who: 'browser',
          text: await expectFailure(() => localDecrypt(dkA.plaintext, a.envelope.iv, bodyA, canonical(b.envelope.encryption_context))),
        });
        return 'Swaps detected';
      } finally {
        await cleanup(a, b);
      }
    },
  },
  {
    id: 'shred',
    title: 'Read data after the key is deleted',
    threat: 'Data that was supposed to be destroyed is still sitting in storage, in backups, or in an attacker\'s copy.',
    defence: (
      <>
        Deleting a <Term k="CMK">CMK</Term> destroys every version of its key material inside the KMS. Without it the wrapped data keys can never be opened, so every copy of
        the ciphertext, anywhere, is permanently unreadable. This is <Term k="SHRED">crypto-shredding</Term>.
      </>
    ),
    run: async (log) => {
      const alice = await as('alice');
      const key = await kms.createKey(alice.token, `lab-shred-${Date.now().toString(36)}`, 'Temporary key for the security lab', 'AES_KW');
      log({ tone: 'info', who: 'alice', text: `Created ${key.alias}` });
      const obj = await labUpload('shred-me.txt', 'Contract draft v3', key.alias);
      try {
        const ok = await kms.decrypt(alice.token, obj.envelope.ciphertext_blob, obj.envelope.encryption_context);
        log({ tone: 'ok', who: 'kms', text: `Before deletion: decrypt works (key v${ok.data.key_version})` });
        await kms.scheduleDeletion(alice.token, key.key_id, 0);
        log({ tone: 'info', who: 'alice', text: 'Scheduled deletion with a zero-minute window: key material destroyed' });
        log({ tone: 'attack', who: 'anyone', text: 'Ciphertext + wrapped key are still in storage. Try to decrypt.' });
        log({ tone: 'blocked', who: 'kms', text: await expectFailure(() => kms.decrypt(alice.token, obj.envelope.ciphertext_blob, obj.envelope.encryption_context)) });
        return 'Data permanently unreadable';
      } finally {
        await cleanup(obj);
      }
    },
  },
];

// ------------------------------------------------------------------------------------------ UI
function AttackCard({ attack, index }: { attack: Attack; index: number }) {
  const [lines, setLines] = useState<Line[]>([]);
  const [state, setState] = useState<'idle' | 'running' | 'done' | 'error'>('idle');
  const [verdict, setVerdict] = useState('');

  const run = async () => {
    setLines([]);
    setState('running');
    try {
      setVerdict(await attack.run((l) => setLines((p) => [...p, l])));
      setState('done');
    } catch (e) {
      setVerdict(errorText(e));
      setState('error');
    }
  };

  return (
    <Container
      header={
        <Header
          variant="h2"
          description={attack.threat}
          actions={
            <Button onClick={run} loading={state === 'running'} variant={state === 'idle' ? 'primary' : 'normal'}>
              {state === 'idle' ? 'Run attack' : 'Run again'}
            </Button>
          }
        >
          <span className="lab-num">{String(index + 1).padStart(2, '0')}</span> {attack.title}
        </Header>
      }
    >
      {state === 'idle' ? (
        <Box color="text-body-secondary" fontSize="body-s">Runs against the live services. Temporary objects are cleaned up afterwards.</Box>
      ) : (
        <SpaceBetween size="m">
          <ol className="lab-log">
            {lines.map((l, i) => (
              <li key={i} className={`lab-line ${l.tone}`}>
                <span className="lab-who">{l.who}</span>
                <span className="lab-text">
                  {l.text}
                  {l.mono && <code>{l.mono}</code>}
                </span>
              </li>
            ))}
          </ol>
          {state === 'done' && (
            <div className="lab-verdict">
              <StatusIndicator type="success">Attack failed: {verdict}</StatusIndicator>
              <Box variant="p" margin={{ top: 'xs' }}>
                <strong>Why:</strong> {attack.defence}
              </Box>
            </div>
          )}
          {state === 'error' && <StatusIndicator type="error">{verdict}</StatusIndicator>}
        </SpaceBetween>
      )}
    </Container>
  );
}

export default function Lab() {
  usePage({ help: 'lab', crumbs: [{ text: 'Security', href: '#' }, { text: 'Security lab', href: '#' }] });
  return (
    <ContentLayout
      header={
        <Header variant="h1" info={<InfoLink topic="lab" />} description="Five real attacks against the live system, each paired with the mechanism that stops it.">
          Security lab
        </Header>
      }
    >
      <SpaceBetween size="l">
        {ATTACKS.map((a, i) => (
          <AttackCard key={a.id} attack={a} index={i} />
        ))}
      </SpaceBetween>
    </ContentLayout>
  );
}
