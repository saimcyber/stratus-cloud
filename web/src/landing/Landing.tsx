import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import './landing.css';

const FILE_LINES = ['Patient 4471', 'Diagnosis: type 2 diabetes', 'Prescribed: metformin 500mg', 'Next review: 12 Jan'];
const HEX = '0123456789abcdef';

// Small integer hash so the 'ciphertext' looks random but is stable between frames.
function mix(a: number, b: number) {
  let h = Math.imul(a ^ 0x9e3779b9, 0x85ebca6b) ^ Math.imul(b + 0x632be5ab, 0xc2b2ae35);
  h ^= h >>> 15;
  h = Math.imul(h, 0x2c1b3c6d);
  return (h ^ (h >>> 12)) >>> 0;
}

function scramble(text: string, progress: number, seed: number) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const flip = mix(i, 7) % 100 < progress * 100;
    if (text[i] === ' ' && progress < 0.6) out += ' ';
    else out += flip ? HEX[mix(i, seed) % 16] : text[i];
  }
  return out;
}

type Phase = 'plain' | 'sealing' | 'sealed';

function HeroVisual() {
  const reduce = useReducedMotion();
  const [phase, setPhase] = useState<Phase>('plain');
  const [progress, setProgress] = useState(0);
  const [seed, setSeed] = useState(1);

  useEffect(() => {
    if (reduce) {
      setPhase('sealed');
      setProgress(1);
      return;
    }
    let raf = 0;
    let t0 = performance.now();
    const cycle = 7200;
    const tick = (now: number) => {
      const t = (now - t0) % cycle;
      if (t < 1600) {
        setPhase('plain');
        setProgress(0);
      } else if (t < 3400) {
        setPhase('sealing');
        setProgress((t - 1600) / 1800);
        setSeed(Math.floor(t / 90));
      } else {
        setPhase('sealed');
        setProgress(1);
      }
      if (now - t0 > cycle * 50) t0 = now;
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [reduce]);

  return (
    <div className="lp-visual" aria-label="A file being encrypted into ciphertext and sealed with a wrapped key">
      <div className={`lp-file ${phase}`}>
        <div className="lp-file-head">
          <span className="lp-dot" />
          <span>patient-4471.txt</span>
          <span className="lp-file-state">{phase === 'plain' ? 'plaintext · in your browser' : phase === 'sealing' ? 'AES-256-GCM' : 'ciphertext · safe to store'}</span>
        </div>
        <div className="lp-file-body">
          {FILE_LINES.map((l, i) => (
            <div key={i} className="lp-line">
              {scramble(l, Math.min(1, Math.max(0, progress * 1.4 - i * 0.12)), seed + i)}
            </div>
          ))}
        </div>
      </div>

      <div className="lp-envelope">
        <AnimatePresence>
          {phase !== 'plain' && (
            <motion.div
              className="lp-dek"
              initial={{ y: -46, opacity: 0, scale: 0.9 }}
              animate={phase === 'sealed' ? { y: 18, opacity: 0, scale: 0.7 } : { y: 0, opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            >
              DEK
            </motion.div>
          )}
        </AnimatePresence>
        <div className={`lp-env-box ${phase === 'sealed' ? 'sealed' : ''}`}>
          <svg viewBox="0 0 120 76" aria-hidden>
            <rect x="1" y="1" width="118" height="74" rx="8" />
            <motion.path
              d="M2 6 L60 44 L118 6"
              initial={false}
              animate={{ pathLength: phase === 'sealed' ? 1 : 0.0001 }}
              transition={{ duration: 0.6 }}
            />
          </svg>
          <motion.span
            className="lp-seal"
            initial={false}
            animate={{ scale: phase === 'sealed' ? 1 : 0, rotate: phase === 'sealed' ? -8 : -30 }}
            transition={{ type: 'spring', stiffness: 260, damping: 16 }}
          >
            CMK v3
          </motion.span>
        </div>
        <div className="lp-env-label">{phase === 'sealed' ? 'wrapped data key · stored beside the file' : 'fresh data key from Stratus KMS'}</div>
      </div>
    </div>
  );
}

const reveal = {
  initial: { opacity: 0, y: 24 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] as const },
};

const TIERS = [
  { tier: '01', name: 'Root KEK', where: 'Inside the KMS only', what: 'Seals every customer key. Never touches data.' },
  { tier: '02', name: 'Customer managed key', where: 'Per tenant, versioned', what: 'Wraps data keys. Rotates without breaking anything.' },
  { tier: '03', name: 'Data key', where: 'Per file, in your browser', what: 'Encrypts one file, then is wiped from memory.' },
];

const PARTIES = [
  { name: 'Your browser', sees: ['the file', 'the data key, for milliseconds'], never: [] as string[] },
  { name: 'Stratus KMS', sees: ['32-byte keys', 'object labels'], never: ['your file'] },
  { name: 'Stratus Vault', sees: ['ciphertext', 'wrapped keys'], never: ['your file', 'any usable key'] },
];

export default function Landing() {
  useEffect(() => {
    document.body.classList.add('lp-body');
    return () => document.body.classList.remove('lp-body');
  }, []);

  return (
    <div className="lp">
      <header className="lp-nav">
        <Link to="/" className="lp-brand">
          <img src="/favicon.svg" alt="" width={26} height={26} />
          <span>Stratus</span>
        </Link>
        <nav>
          <a href="#hierarchy">How it works</a>
          <a href="#boundaries">Security</a>
          <Link to="/console" className="lp-nav-cta">
            Sign in to console
          </Link>
        </nav>
      </header>

      <section className="lp-hero">
        <div className="lp-hero-copy">
          <motion.p className="lp-eyebrow" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
            Envelope encryption · Key management
          </motion.p>
          <motion.h1 initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}>
            Your files, <em>sealed</em>
            <br /> before they leave.
          </motion.h1>
          <motion.p className="lp-sub" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2, duration: 0.7 }}>
            Your browser encrypts. The cloud keeps ciphertext. The keys stay in a hierarchy only the KMS can open.
          </motion.p>
          <motion.div className="lp-ctas" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.35 }}>
            <Link to="/console" className="lp-btn primary">
              Open the console <span aria-hidden>→</span>
            </Link>
            <a href="#hierarchy" className="lp-btn ghost">
              How it works
            </a>
          </motion.div>
        </div>
        <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.2, duration: 0.9 }}>
          <HeroVisual />
        </motion.div>
      </section>

      <div className="lp-specs" aria-label="Algorithms">
        {['AES-256-GCM', 'RFC 3394 Key Wrap', 'RSA-2048-OAEP', 'HMAC-bound context', 'Crypto-shredding'].map((s) => (
          <span key={s}>{s}</span>
        ))}
      </div>

      <section className="lp-section" id="hierarchy">
        <motion.div className="lp-section-head" {...reveal}>
          <p className="lp-kicker">The hierarchy</p>
          <h2>
            Three keys. <em>Three places.</em>
          </h2>
        </motion.div>
        <div className="lp-strata">
          {TIERS.map((t, i) => (
            <motion.div key={t.tier} className={`lp-stratum s${i}`} {...reveal} transition={{ ...reveal.transition, delay: i * 0.12 }}>
              <span className="lp-tier">{t.tier}</span>
              <div>
                <h3>{t.name}</h3>
                <p className="lp-where">{t.where}</p>
              </div>
              <p className="lp-what">{t.what}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="lp-section dark" id="boundaries">
        <motion.div className="lp-section-head" {...reveal}>
          <p className="lp-kicker">Trust boundaries</p>
          <h2>
            Built so the cloud <em>can't look.</em>
          </h2>
        </motion.div>
        <div className="lp-parties">
          {PARTIES.map((p, i) => (
            <motion.div key={p.name} className={`lp-party ${i === 2 ? 'untrusted' : ''}`} {...reveal} transition={{ ...reveal.transition, delay: i * 0.1 }}>
              <h3>{p.name}</h3>
              <ul>
                {p.sees.map((s) => (
                  <li key={s}>{s}</li>
                ))}
                {p.never.map((s) => (
                  <li key={s} className="never">
                    {s}
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-life">
          {[
            ['Rotate', 'New key version in one click. Old files keep opening; re-wrapping moves 300 bytes, not the file.'],
            ['Revoke', 'Remove a user, disable a key, or lock out brute force. Effective on the very next request.'],
            ['Shred', 'Delete a key and every copy of its data, backups included, becomes unreadable for good.'],
          ].map(([t, d], i) => (
            <motion.div key={t} className="lp-life-card" {...reveal} transition={{ ...reveal.transition, delay: i * 0.1 }}>
              <span className="lp-life-n">{String(i + 1).padStart(2, '0')}</span>
              <h3>{t}</h3>
              <p>{d}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="lp-final">
        <motion.h2 {...reveal}>
          Now try to <em>break it.</em>
        </motion.h2>
        <motion.div {...reveal} transition={{ ...reveal.transition, delay: 0.1 }}>
          <Link to="/console/lab" className="lp-btn primary">
            Open the security lab <span aria-hidden>→</span>
          </Link>
        </motion.div>
      </section>

      <footer className="lp-foot">
        <span>Stratus Cloud · CS-3002 Information Security term project · FAST NUCES Islamabad</span>
        <span>A teaching model. Not affiliated with any cloud provider.</span>
      </footer>
    </div>
  );
}
