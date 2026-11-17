import { AnimatePresence, motion } from 'framer-motion';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import type { EnvelopeEvent } from '../lib/envelope';
import { formatBytes } from '../lib/envelope';
import Term from './Term';
import * as awsui from '@cloudscape-design/design-tokens';
import './inspector.css';

type Mode = 'encrypt' | 'decrypt';
const TOKENS = {
  '--ins-bg': awsui.colorBackgroundContainerHeader,
  '--ins-surface': awsui.colorBackgroundContainerContent,
  '--ins-border': awsui.colorBorderDividerDefault,
} as React.CSSProperties;

const LANES = ['Your browser', 'Stratus KMS', 'Stratus Vault'] as const;

interface Packet {
  from: number;
  to: number;
  label: string;
  tone: 'key' | 'data' | 'wrapped';
}

function packetFor(e: EnvelopeEvent | undefined, mode: Mode): Packet | null {
  if (!e) return null;
  switch (e.kind) {
    case 'request-dek':
      return { from: 0, to: 1, label: 'GenerateDataKey + context', tone: 'wrapped' };
    case 'fetch-ciphertext':
      return { from: 2, to: 0, label: 'ciphertext + wrapped DEK', tone: 'data' };
    case 'dek-received':
      return mode === 'encrypt'
        ? { from: 1, to: 0, label: 'DEK + wrapped DEK', tone: 'key' }
        : { from: 1, to: 0, label: 'DEK (unwrapped)', tone: 'key' };
    case 'uploaded':
      return { from: 0, to: 2, label: 'ciphertext + wrapped DEK', tone: 'data' };
    default:
      return null;
  }
}

function holdings(events: EnvelopeEvent[], mode: Mode): string[][] {
  const has = (k: EnvelopeEvent['kind']) => events.some((e) => e.kind === k);
  const browser: string[] = [];
  const kmsHeld = ['Root KEK', 'CMK versions'];
  const vaultHeld: string[] = [];
  if (mode === 'encrypt') {
    browser.push('plaintext file');
    if (has('dek-received') && !has('zeroized')) browser.push('DEK (raw bytes)');
    if (has('zeroized')) browser.push('DEK handle (non-extractable)');
    if (has('encrypted')) browser.push('ciphertext');
    if (has('request-dek')) kmsHeld.push('encryption context');
    if (has('uploaded')) vaultHeld.push('ciphertext', 'wrapped DEK', 'IV + context');
  } else {
    vaultHeld.push('ciphertext', 'wrapped DEK', 'IV + context');
    if (has('fetch-ciphertext')) browser.push('ciphertext', 'wrapped DEK');
    if (has('dek-received') && !has('zeroized')) browser.push('DEK (raw bytes)');
    if (has('zeroized')) browser.push('DEK handle (non-extractable)');
    if (has('decrypted')) browser.push('plaintext file');
    if (has('dek-received')) kmsHeld.push('wrapped DEK', 'encryption context');
  }
  return [browser, kmsHeld, vaultHeld];
}

function DekGrid({ dek, wiped }: { dek: Uint8Array | null; wiped: boolean }) {
  const cells = Array.from({ length: 32 }, (_, i) => (dek ? dek[i] : 1));
  return (
    <div className="ins-grid" aria-label={wiped ? 'Data key bytes overwritten with zeros' : 'Data key bytes held in memory'}>
      {cells.map((b, i) => (
        <motion.span
          key={`${i}-${b === 0}`}
          className={b === 0 ? 'ins-cell zero' : 'ins-cell live'}
          initial={wiped ? { rotateX: 90, opacity: 0.2 } : false}
          animate={{ rotateX: 0, opacity: 1 }}
          transition={{ delay: wiped ? i * 0.018 : 0, duration: 0.25 }}
        >
          {b === 0 ? '00' : '••'}
        </motion.span>
      ))}
    </div>
  );
}

const ENCRYPT_STEPS = [
  { kind: 'request-dek', title: 'Request a fresh data key from the KMS' },
  { kind: 'dek-received', title: 'Receive the DEK and its wrapped copy' },
  { kind: 'zeroized', title: 'Import as non-extractable key, wipe raw bytes' },
  { kind: 'encrypted', title: 'Encrypt locally with AES-256-GCM' },
  { kind: 'uploaded', title: 'Store ciphertext + wrapped DEK in the Vault' },
] as const;

const DECRYPT_STEPS = [
  { kind: 'fetch-ciphertext', title: 'Fetch ciphertext + wrapped DEK from the Vault' },
  { kind: 'dek-received', title: 'KMS checks access, unwraps the DEK' },
  { kind: 'zeroized', title: 'Import as non-extractable key, wipe raw bytes' },
  { kind: 'decrypted', title: 'Decrypt and verify locally with AES-256-GCM' },
] as const;

function detail(e: EnvelopeEvent) {
  switch (e.kind) {
    case 'request-dek':
      return (
        <>
          <Term k="CONTEXT">Encryption context</Term> sent: <code>{JSON.stringify(e.ctx)}</code>
          <div className="ins-note">The KMS receives labels only. The file stays in this tab.</div>
        </>
      );
    case 'fetch-ciphertext':
      return (
        <>
          {formatBytes(e.bytes)} downloaded in {e.ms.toFixed(0)} ms
          <pre className="ins-hex">{e.preview}</pre>
        </>
      );
    case 'dek-received':
      return (
        <>
          {e.keyAlias} v{e.version} · {e.algorithm === 'AES_KW' ? 'AES Key Wrap (RFC 3394)' : 'RSA-2048-OAEP'} ·{' '}
          {e.ms.toFixed(0)} ms
          <div className="ins-label">
            <Term k="WRAPPED">Wrapped DEK</Term> ({e.blobBytes} bytes)
          </div>
          <pre className="ins-hex">{e.blobPreview}</pre>
        </>
      );
    case 'zeroized':
      return (
        <>
          <div className="ins-label">
            <Term k="DEK">DEK</Term> memory, 32 bytes. Never displayed; only its state is shown.
          </div>
          <DekGrid dek={e.dek} wiped />
          <div className="ins-note">
            <Term k="ZEROIZE">Zeroized</Term>: only a non-extractable CryptoKey handle remains.
          </div>
        </>
      );
    case 'encrypted':
      return (
        <>
          IV <code>{e.iv}</code> · {formatBytes(e.bytes)} incl. 16-byte tag · {e.ms.toFixed(1)} ms
          <div className="ins-split">
            <div>
              <div className="ins-label">Plaintext (stays here)</div>
              <pre className="ins-hex plain">{e.plainPreview || '(binary)'}</pre>
            </div>
            <div>
              <div className="ins-label">Ciphertext (leaves)</div>
              <pre className="ins-hex">{e.cipherPreview}</pre>
            </div>
          </div>
          <div className="ins-note">
            <Term k="GCM">AAD</Term>: <code>{e.aad}</code>
          </div>
        </>
      );
    case 'decrypted':
      return (
        <>
          Tag verified · {formatBytes(e.bytes)} · {e.ms.toFixed(1)} ms
          <pre className="ins-hex plain">{e.plainPreview || '(binary)'}</pre>
        </>
      );
    case 'uploaded':
      return (
        <>
          Stored {formatBytes(e.object.stored_size)} in {e.ms.toFixed(0)} ms · SHA-256{' '}
          <code>{e.object.ciphertext_sha256.slice(0, 16)}…</code>
        </>
      );
    default:
      return null;
  }
}

export default function Inspector({
  mode,
  events,
  error,
}: {
  mode: Mode;
  events: EnvelopeEvent[];
  error?: string | null;
}) {
  const last = [...events].reverse().find((e) => packetFor(e, mode));
  const packet = packetFor(last, mode);
  const lastKind = events.at(-1)?.kind;
  const lanes = holdings(events, mode);
  const steps = mode === 'encrypt' ? ENCRYPT_STEPS : DECRYPT_STEPS;
  const done = lastKind === 'done';

  return (
    <div style={TOKENS}>
    <SpaceBetween size="l">
      <div className="ins-stage">
        <div className="ins-lanes">
          {LANES.map((name, i) => (
            <div key={name} className={`ins-lane ${i === 2 ? 'untrusted' : ''}`}>
              <div className="ins-lane-title">
                {name}
                {i === 2 && <span className="ins-tag">untrusted</span>}
              </div>
              <AnimatePresence initial={false}>
                {lanes[i].map((h) => (
                  <motion.div
                    key={h}
                    className={`ins-chip ${/DEK \(raw/.test(h) ? 'hot' : ''} ${/plaintext/.test(h) ? 'plain' : ''}`}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.9 }}
                    transition={{ duration: 0.25 }}
                  >
                    {h}
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          ))}
        </div>
        <div className="ins-track" aria-hidden>
          <AnimatePresence>
            {packet && !done && (
              <motion.div
                key={`${last?.kind}-${packet.from}-${packet.to}`}
                className={`ins-packet ${packet.tone}`}
                initial={{ left: `${packet.from * 33.333 + 16.666}%`, opacity: 0 }}
                animate={{ left: `${packet.to * 33.333 + 16.666}%`, opacity: [0, 1, 1, 0.85] }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
              >
                {packet.label}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      <ol className="ins-steps">
        {steps.map((s, i) => {
          const ev = events.find((e) => e.kind === s.kind);
          const completed = steps.filter((st) => events.some((e) => e.kind === st.kind)).length;
          const status = ev ? 'success' : i === completed ? (error ? 'error' : 'in-progress') : 'pending';
          return (
            <li key={s.kind} className={`ins-step ${status}`}>
              <StatusIndicator type={status === 'pending' ? 'pending' : status}>{s.title}</StatusIndicator>
              {ev && (
                <motion.div className="ins-detail" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}>
                  {detail(ev)}
                </motion.div>
              )}
            </li>
          );
        })}
      </ol>
      {error && (
        <Box color="text-status-error" variant="p">
          {error}
        </Box>
      )}
    </SpaceBetween>
    </div>
  );
}
