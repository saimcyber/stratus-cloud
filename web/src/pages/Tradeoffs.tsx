import { useState } from 'react';
import BarChart from '@cloudscape-design/components/bar-chart';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import LineChart from '@cloudscape-design/components/line-chart';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import { kms } from '../lib/api';
import { errorText } from '../lib/session';
import { InfoLink, usePage } from '../console/Shell';

const SIZES = [16, 256, 1024, 4096, 10240]; // KB
const label = (kb: number) => (kb >= 1024 ? `${kb / 1024} MB` : `${kb} KB`);
const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

interface Results {
  gcm: { size: string; kb: number; enc: number; dec: number; mbps: number }[];
  wrap: { op: string; aes: number; rsa: number }[];
  rewrapMs: number;
  dataKeyMs: number;
}

async function runBench(progress: (p: number, msg: string) => void): Promise<Results> {
  // 1. Local AES-256-GCM cost by size
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const gcm: Results['gcm'] = [];
  for (const [i, kb] of SIZES.entries()) {
    progress(5 + i * 8, `AES-256-GCM on ${label(kb)}`);
    const data = new Uint8Array(kb * 1024);
    for (let off = 0; off < data.length; off += 65536) crypto.getRandomValues(data.subarray(off, off + 65536));
    const encT: number[] = [];
    const decT: number[] = [];
    for (let r = 0; r < 3; r++) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      let t = performance.now();
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
      encT.push(performance.now() - t);
      t = performance.now();
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      decT.push(performance.now() - t);
    }
    const enc = median(encT);
    gcm.push({ size: label(kb), kb, enc, dec: median(decT), mbps: kb / 1024 / (enc / 1000) });
  }

  // 2. Wrapping algorithms: server-side cost of GenerateDataKey / Decrypt (AES-KW vs RSA-OAEP)
  const alice = await kms.demoLogin('alice');
  const keys = await kms.keys(alice.token);
  const aes = keys.find((k) => k.alias === 'alias/patient-records' && k.state === 'Enabled');
  const rsa = keys.find((k) => k.algorithm === 'RSA_2048_OAEP' && k.state === 'Enabled');
  if (!aes || !rsa) throw new Error('Benchmark needs alias/patient-records and an enabled RSA key in Acme Health');
  const ctx = { tenant: 'acme-health', bucket: 'bench', object: 'bench.bin' };
  const sample = async (keyId: string) => {
    const gen: number[] = [];
    const dec: number[] = [];
    let blob = '';
    for (let r = 0; r < 12; r++) {
      const g = await kms.generateDataKey(alice.token, keyId, ctx);
      gen.push(g.serverMs);
      blob = g.data.ciphertext_blob;
      const d = await kms.decrypt(alice.token, blob, ctx);
      dec.push(d.serverMs);
    }
    return { gen: median(gen), dec: median(dec), blob };
  };
  progress(50, 'AES Key Wrap: 12 data keys');
  const a = await sample(aes.key_id);
  progress(65, 'RSA-2048-OAEP: 12 data keys');
  const r = await sample(rsa.key_id);

  // 3. Rotation: re-wrap (one small KMS call) — measured end to end from the browser
  progress(82, 'ReEncrypt round trips');
  const rewrap: number[] = [];
  const dk: number[] = [];
  for (let i = 0; i < 6; i++) {
    rewrap.push((await kms.reEncrypt(alice.token, a.blob, ctx)).totalMs);
    dk.push((await kms.generateDataKey(alice.token, aes.key_id, ctx)).totalMs);
  }
  progress(100, 'Done');
  return {
    gcm,
    wrap: [
      { op: 'GenerateDataKey', aes: a.gen, rsa: r.gen },
      { op: 'Decrypt', aes: a.dec, rsa: r.dec },
    ],
    rewrapMs: mean(rewrap),
    dataKeyMs: mean(dk),
  };
}

export default function Tradeoffs() {
  usePage({ help: 'tradeoffs', crumbs: [{ text: 'Security', href: '#' }, { text: 'Trade-offs', href: '#' }] });
  const [res, setRes] = useState<Results | null>(null);
  const [running, setRunning] = useState(false);
  const [prog, setProg] = useState({ p: 0, msg: '' });
  const [error, setError] = useState<string | null>(null);

  const start = async () => {
    setRunning(true);
    setError(null);
    try {
      const r = await runBench((p, msg) => setProg({ p, msg }));
      console.info('[stratus-bench]', JSON.stringify(r)); // raw numbers for the report
      setRes(r);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setRunning(false);
    }
  };

  const rotationSeries = res
    ? [
        {
          title: 'Re-wrap data key (envelope)',
          type: 'line' as const,
          data: res.gcm.map((g) => ({ x: g.size, y: +res.rewrapMs.toFixed(1) })),
        },
        {
          title: 'Re-encrypt the whole file (crypto only, no transfer)',
          type: 'line' as const,
          data: res.gcm.map((g) => ({ x: g.size, y: +(g.enc + g.dec).toFixed(1) })),
        },
      ]
    : [];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          info={<InfoLink topic="tradeoffs" />}
          description="What each security choice costs, measured live from your browser against the running services."
          actions={
            <Button variant="primary" loading={running} onClick={start}>
              {res ? 'Run again' : 'Run benchmarks'}
            </Button>
          }
        >
          Security vs. usability
        </Header>
      }
    >
      <SpaceBetween size="l">
        {running && (
          <Container>
            <ProgressBar value={prog.p} label="Benchmarking" additionalInfo={prog.msg} />
          </Container>
        )}
        {error && <Box color="text-status-error">{error}</Box>}

        {res && (
          <>
            <Container header={<Header variant="h2" description="Where the time goes for one upload.">Headline numbers</Header>}>
              <ColumnLayout columns={4} variant="text-grid" minColumnWidth={150}>
                <div>
                  <Box variant="awsui-key-label">Data key round trip</Box>
                  <Box variant="awsui-value-large">{res.dataKeyMs.toFixed(0)} ms</Box>
                  <Box fontSize="body-s" color="text-body-secondary">One per upload, any file size</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">AES-GCM throughput</Box>
                  <Box variant="awsui-value-large">{res.gcm.at(-1)!.mbps.toFixed(0)} MB/s</Box>
                  <Box fontSize="body-s" color="text-body-secondary">In this browser, 10 MB file</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">RSA vs AES-KW unwrap</Box>
                  <Box variant="awsui-value-large">{(res.wrap[1].rsa / Math.max(res.wrap[1].aes, 0.01)).toFixed(1)}×</Box>
                  <Box fontSize="body-s" color="text-body-secondary">Server time per Decrypt</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">Storage overhead</Box>
                  <Box variant="awsui-value-large">16 B</Box>
                  <Box fontSize="body-s" color="text-body-secondary">GCM tag, plus a ~100 B wrapped key</Box>
                </div>
              </ColumnLayout>
            </Container>

            <ColumnLayout columns={2}>
              <Container header={<Header variant="h2" description="Median of 3 runs, Web Crypto API.">AES-256-GCM cost by file size</Header>}>
                <BarChart
                  series={[
                    { title: 'Encrypt', type: 'bar', data: res.gcm.map((g) => ({ x: g.size, y: +g.enc.toFixed(2) })) },
                    { title: 'Decrypt', type: 'bar', data: res.gcm.map((g) => ({ x: g.size, y: +g.dec.toFixed(2) })) },
                  ]}
                  xTitle="File size"
                  yTitle="Milliseconds"
                  height={240}
                  hideFilter
                  empty="No data"
                  ariaLabel="AES-GCM timings"
                />
              </Container>
              <Container header={<Header variant="h2" description="Median server time over 12 calls each.">Wrapping algorithm cost</Header>}>
                <BarChart
                  series={[
                    { title: 'AES-256 Key Wrap', type: 'bar', data: res.wrap.map((w) => ({ x: w.op, y: +w.aes.toFixed(2) })) },
                    { title: 'RSA-2048-OAEP', type: 'bar', data: res.wrap.map((w) => ({ x: w.op, y: +w.rsa.toFixed(2) })) },
                  ]}
                  xTitle="KMS operation"
                  yTitle="Milliseconds (server)"
                  height={240}
                  hideFilter
                  empty="No data"
                  ariaLabel="Wrapping algorithm timings"
                />
              </Container>
            </ColumnLayout>

            <Container
              header={
                <Header variant="h2" description="Envelope encryption makes key rotation cost the same for a 16 KB note and a 10 MB scan.">
                  Rotating one object: re-wrap vs. re-encrypt
                </Header>
              }
            >
              <LineChart
                series={rotationSeries}
                xScaleType="categorical"
                xTitle="File size"
                yTitle="Milliseconds"
                height={260}
                hideFilter
                empty="No data"
                ariaLabel="Rotation cost"
              />
              <Box fontSize="body-s" color="text-body-secondary" margin={{ top: 's' }}>
                Re-encrypting also means downloading and re-uploading the full file, so the real gap is wider than shown. Re-wrapping moves about 300 bytes.
              </Box>
            </Container>
          </>
        )}

        <Table
          header={<Header variant="h2" description="The design decisions behind Stratus and what each one costs.">Trade-offs we chose</Header>}
          wrapLines
          items={[
            { c: 'Encrypt in the browser', g: 'The storage server never sees a file or a usable key', x: 'No server-side search or previews; the whole file is held in memory (10 MB cap)' },
            { c: 'A fresh data key per object', g: 'One leaked key exposes one object; random 96-bit IVs never repeat under the same key', x: 'One extra KMS round trip per upload' },
            { c: 'RSA-2048-OAEP wrapping (optional)', g: 'The wrapping key can be public; only the KMS can unwrap', x: 'Unwrap is several times slower than AES Key Wrap (see chart)' },
            { c: 'Encryption-context binding', g: 'Stops swap and replay of keys or ciphertext between objects', x: 'A 32-byte HMAC per wrapped key; the context must be stored and re-sent' },
            { c: 'Rotation keeps old versions', g: 'Rotating never breaks existing data', x: 'Old key versions stay live until objects are re-wrapped' },
            { c: '7-30 day deletion window', g: 'Protects against accidental or malicious crypto-shredding', x: 'Revocation by deletion is slow; disable or remove access for an immediate stop' },
            { c: 'Rate limits and lockout', g: 'Brute-force and denial attempts get throttled', x: 'Legitimate bursts above 100 calls/s per user are slowed down' },
          ]}
          columnDefinitions={[
            { id: 'c', header: 'Choice', cell: (i) => <strong>{i.c}</strong> },
            { id: 'g', header: 'Security gained', cell: (i) => i.g },
            { id: 'x', header: 'Cost', cell: (i) => i.x },
          ]}
        />
      </SpaceBetween>
    </ContentLayout>
  );
}
