import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Checkbox from '@cloudscape-design/components/checkbox';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FileUpload from '@cloudscape-design/components/file-upload';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Modal from '@cloudscape-design/components/modal';
import SegmentedControl from '@cloudscape-design/components/segmented-control';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import Textarea from '@cloudscape-design/components/textarea';
import { kms, vault, type Cmk, type StoredObject } from '../lib/api';
import {
  b64,
  downloadBytes,
  encryptAndUpload,
  fetchAndDecrypt,
  formatBytes,
  hex,
  isText,
  rewrapObject,
  utf8Decoder,
  utf8Encoder,
  type EnvelopeEvent,
} from '../lib/envelope';
import { errorText, useAuthed } from '../lib/session';
import { timeAgo, useLoad } from '../lib/useLoad';
import { Hot, InfoLink, usePage } from '../console/Shell';
import Inspector from '../components/Inspector';
import Term from '../components/Term';

const MAX_BYTES = 10 * 1024 * 1024;
const PACE = 650;
const SAMPLE = 'Patient 4473\nDiagnosis: seasonal allergies\nNotes: this text is encrypted in your browser before upload.\n';

type ObjStatus = 'ok' | 'rewrap' | 'disabled' | 'gone' | 'unknown';

function objStatus(o: StoredObject, keys: Map<string, Cmk>): ObjStatus {
  const k = keys.get(o.envelope.kms_key_id);
  if (!k) return 'unknown';
  if (k.state === 'Deleted') return 'gone';
  if (k.state !== 'Enabled') return 'disabled';
  return o.envelope.kms_key_version < k.primary_version ? 'rewrap' : 'ok';
}

export default function BucketDetail() {
  const { bucket = '' } = useParams();
  const { token, user, notify } = useAuthed();
  usePage({
    help: 'bucket',
    crumbs: [
      { text: 'Vault', href: '/console/vault/buckets' },
      { text: 'Buckets', href: '/console/vault/buckets' },
      { text: bucket, href: '#' },
    ],
  });

  const objects = useLoad(() => vault.objects(token, bucket), [token, bucket]);
  const keyList = useLoad(() => kms.keys(token), [token]);
  const keys = useMemo(() => new Map((keyList.data ?? []).map((k) => [k.key_id, k])), [keyList.data]);
  const [selected, setSelected] = useState<StoredObject[]>([]);
  const [modal, setModal] = useState<'upload' | 'open' | 'raw' | null>(null);
  const [rewrapping, setRewrapping] = useState(false);

  const refresh = () => {
    objects.reload();
    keyList.reload();
  };
  const outdated = (objects.data ?? []).filter((o) => objStatus(o, keys) === 'rewrap');
  const one = selected.length === 1 ? selected[0] : null;

  const rewrap = async () => {
    const targets = selected.some((o) => objStatus(o, keys) === 'rewrap') ? selected.filter((o) => objStatus(o, keys) === 'rewrap') : outdated;
    setRewrapping(true);
    let done = 0;
    try {
      // Re-wraps run concurrently; each is one small KMS call, the payload is never downloaded.
      await Promise.all(targets.map((o) => rewrapObject(token, bucket, o).then(() => done++)));
      notify({ type: 'success', content: `Re-wrapped ${done} object${done === 1 ? '' : 's'} under the current key version. Ciphertext unchanged.` });
    } catch (e) {
      notify({ type: 'error', header: `Re-wrapped ${done} of ${targets.length}`, content: errorText(e) });
    } finally {
      setRewrapping(false);
      setSelected([]);
      refresh();
    }
  };

  const remove = async () => {
    for (const o of selected) {
      try {
        await vault.deleteObject(token, bucket, o.id);
      } catch (e) {
        notify({ type: 'error', content: errorText(e) });
      }
    }
    setSelected([]);
    refresh();
  };

  return (
    <ContentLayout
      header={
        <Header variant="h1" info={<InfoLink topic="bucket" />} description={`Owned by ${user.tenant_name}. Objects are encrypted client-side; the Vault never holds a usable key.`}>
          {bucket}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {objects.error && <Alert type="error">{objects.error}</Alert>}
        {outdated.length > 0 && (
          <Alert
            type="info"
            header={`${outdated.length} object${outdated.length > 1 ? 's' : ''} wrapped under an older key version`}
            action={
              <Hot id="rewrap-button" side="left">
                <Button loading={rewrapping} onClick={rewrap}>Re-wrap all</Button>
              </Hot>
            }
          >
            They still decrypt. Re-wrapping asks the KMS to move each <Term k="WRAPPED">wrapped data key</Term> to the current version. The files themselves are not touched.
          </Alert>
        )}
        <Table<StoredObject>
          variant="full-page"
          loading={objects.loading && !objects.data}
          loadingText="Loading objects"
          items={objects.data ?? []}
          trackBy="id"
          selectionType="multi"
          selectedItems={selected}
          onSelectionChange={(e) => setSelected(e.detail.selectedItems)}
          header={
            <Header
              counter={objects.data ? `(${objects.data.length})` : undefined}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button iconName="refresh" ariaLabel="Refresh" onClick={refresh} />
                  <Hot id="raw-view">
                    <Button disabled={!one} onClick={() => setModal('raw')}>Raw view</Button>
                  </Hot>
                  <Button disabled={!one} onClick={() => setModal('open')}>Open</Button>
                  {outdated.length === 0 && (
                    <Hot id="rewrap-button">
                      <Button disabled loading={rewrapping}>Re-wrap</Button>
                    </Hot>
                  )}
                  <Button disabled={selected.length === 0} onClick={remove}>Delete</Button>
                  <Hot id="upload-button">
                    <Button variant="primary" iconName="upload" onClick={() => setModal('upload')}>Upload</Button>
                  </Hot>
                </SpaceBetween>
              }
            >
              Objects
            </Header>
          }
          empty={
            <Box textAlign="center" padding="l">
              <SpaceBetween size="s">
                <b>No objects</b>
                <Button onClick={() => setModal('upload')}>Upload your first file</Button>
              </SpaceBetween>
            </Box>
          }
          columnDefinitions={[
            { id: 'key', header: 'Name', isRowHeader: true, cell: (o) => o.object_key },
            { id: 'size', header: 'Size', cell: (o) => formatBytes(o.plaintext_size) },
            {
              id: 'cmk',
              header: 'Protected by',
              cell: (o) => {
                const k = keys.get(o.envelope.kms_key_id);
                return `${k?.alias ?? o.envelope.kms_key_id.slice(0, 8)} v${o.envelope.kms_key_version}`;
              },
            },
            {
              id: 'status',
              header: 'Encryption',
              cell: (o) => {
                switch (objStatus(o, keys)) {
                  case 'ok':
                    return <StatusIndicator type="success">Envelope-encrypted</StatusIndicator>;
                  case 'rewrap':
                    return <StatusIndicator type="info">Needs re-wrap</StatusIndicator>;
                  case 'disabled':
                    return <StatusIndicator type="stopped">Key unavailable</StatusIndicator>;
                  case 'gone':
                    return <StatusIndicator type="error">Crypto-shredded</StatusIndicator>;
                  default:
                    return <StatusIndicator type="warning">Key not visible</StatusIndicator>;
                }
              },
            },
            { id: 'by', header: 'Uploaded by', cell: (o) => o.uploaded_by },
            { id: 'when', header: 'Last modified', cell: (o) => timeAgo(o.rewrapped_at ?? o.created_at) },
          ]}
        />
      </SpaceBetween>

      {modal === 'upload' && (
        <UploadModal
          bucket={bucket}
          keys={keyList.data ?? []}
          onClose={() => setModal(null)}
          onUploaded={() => refresh()}
          onShowRaw={(o) => {
            setSelected([o]);
            setModal('raw');
          }}
        />
      )}
      {modal === 'open' && one && <OpenModal bucket={bucket} obj={one} onClose={() => setModal(null)} />}
      {modal === 'raw' && one && <RawModal bucket={bucket} obj={one} onClose={() => setModal(null)} />}
    </ContentLayout>
  );
}

// ------------------------------------------------------------------------------------------ upload
function UploadModal({
  bucket,
  keys,
  onClose,
  onUploaded,
  onShowRaw,
}: {
  bucket: string;
  keys: Cmk[];
  onClose: () => void;
  onUploaded: () => void;
  onShowRaw: (o: StoredObject) => void;
}) {
  const { token, user } = useAuthed();
  const usable = keys.filter((k) => k.state === 'Enabled' && k.my_role);
  const [source, setSource] = useState<'text' | 'file'>('text');
  const [files, setFiles] = useState<File[]>([]);
  const [text, setText] = useState(SAMPLE);
  const [name, setName] = useState('notes/patient-4473.txt');
  const [keyId, setKeyId] = useState<string | null>(usable[0]?.key_id ?? null);
  const [inspect, setInspect] = useState(true);
  const [events, setEvents] = useState<EnvelopeEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<StoredObject | null>(null);

  const file = files[0];
  const tooBig = source === 'file' && file && file.size > MAX_BYTES;
  const ready = !!keyId && name.trim() && (source === 'text' ? text.length > 0 : !!file) && !tooBig;

  const start = async () => {
    if (!keyId) return;
    setEvents([]);
    setError(null);
    try {
      const data = source === 'text' ? utf8Encoder.encode(text) : new Uint8Array(await file!.arrayBuffer());
      const obj = await encryptAndUpload(
        {
          token,
          tenant: user.tenant_id,
          bucket,
          objectKey: name.trim(),
          data,
          contentType: source === 'text' ? 'text/plain' : file!.type || 'application/octet-stream',
          keyId,
        },
        (e) => setEvents((prev) => [...(prev ?? []), e]),
        inspect ? PACE : 0,
      );
      setResult(obj);
      onUploaded();
      if (!inspect) onClose();
    } catch (e) {
      setError(errorText(e));
    }
  };

  const running = events !== null;
  return (
    <Modal
      visible
      size="large"
      onDismiss={onClose}
      header={running ? `Envelope Inspector: encrypting ${name}` : `Upload to ${bucket}`}
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            {!running && <Button variant="link" onClick={onClose}>Cancel</Button>}
            {!running && <Button variant="primary" disabled={!ready} onClick={start}>Encrypt and upload</Button>}
            {result && <Button onClick={() => onShowRaw(result)}>See what the server stored</Button>}
            {running && (result || error) && <Button variant="primary" onClick={onClose}>Done</Button>}
          </SpaceBetween>
        </Box>
      }
    >
      {running ? (
        <Inspector mode="encrypt" events={events} error={error} />
      ) : (
        <SpaceBetween size="l">
          <SegmentedControl
            selectedId={source}
            onChange={(e) => setSource(e.detail.selectedId as 'text' | 'file')}
            options={[{ id: 'text', text: 'Type text' }, { id: 'file', text: 'Choose a file' }]}
            label="Source"
          />
          {source === 'text' ? (
            <FormField label="Contents" description="Anything you type here is encrypted in this browser tab.">
              <Textarea value={text} onChange={(e) => setText(e.detail.value)} rows={4} />
            </FormField>
          ) : (
            <FormField label="File" errorText={tooBig ? 'Files are limited to 10 MB on the free deployment.' : undefined}>
              <FileUpload
                value={files}
                onChange={(e) => {
                  setFiles(e.detail.value);
                  if (e.detail.value[0]) setName(e.detail.value[0].name);
                }}
                showFileSize
                showFileLastModified
                constraintText="Up to 10 MB"
                i18nStrings={{
                  uploadButtonText: (m) => (m ? 'Choose files' : 'Choose file'),
                  dropzoneText: (m) => (m ? 'Drop files to upload' : 'Drop file to upload'),
                  removeFileAriaLabel: (i) => `Remove file ${i + 1}`,
                  limitShowFewer: 'Show fewer files',
                  limitShowMore: 'Show more files',
                  errorIconAriaLabel: 'Error',
                  warningIconAriaLabel: 'Warning',
                }}
              />
            </FormField>
          )}
          <FormField label="Object name">
            <Input value={name} onChange={(e) => setName(e.detail.value)} />
          </FormField>
          <FormField
            label="Customer managed key"
            description={<>The KMS generates a fresh <Term k="DEK">data key</Term> and wraps it under this key.</>}
            errorText={usable.length === 0 ? 'You have no usable keys. Ask a key admin for access.' : undefined}
          >
            <Select
              selectedOption={keyId ? { value: keyId, label: usable.find((k) => k.key_id === keyId)?.alias } : null}
              options={usable.map((k) => ({
                value: k.key_id,
                label: k.alias,
                description: `${k.algorithm === 'AES_KW' ? 'AES-256 Key Wrap' : 'RSA-2048-OAEP'} · v${k.primary_version}`,
              }))}
              onChange={(e) => setKeyId(e.detail.selectedOption.value ?? null)}
            />
          </FormField>
          <Checkbox checked={inspect} onChange={(e) => setInspect(e.detail.checked)} description="Slows the flow down so you can watch each step.">
            Show the Envelope Inspector
          </Checkbox>
        </SpaceBetween>
      )}
    </Modal>
  );
}

// ------------------------------------------------------------------------------------------ open
function OpenModal({ bucket, obj, onClose }: { bucket: string; obj: StoredObject; onClose: () => void }) {
  const { token } = useAuthed();
  const [events, setEvents] = useState<EnvelopeEvent[]>([]);
  const [plain, setPlain] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return; // run once, even under StrictMode's double effects
    started.current = true;
    fetchAndDecrypt(token, bucket, obj, (e) => setEvents((p) => [...p, e]), PACE)
      .then(setPlain)
      .catch((e) => setError(e instanceof DOMException ? 'AES-GCM authentication failed: the ciphertext was modified.' : errorText(e)));
  }, [token, bucket, obj]);

  return (
    <Modal
      visible
      size="large"
      onDismiss={onClose}
      header={`Envelope Inspector: decrypting ${obj.object_key}`}
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            {plain && <Button iconName="download" onClick={() => downloadBytes(plain, obj.object_key, obj.content_type)}>Download</Button>}
            <Button variant="primary" onClick={onClose}>Close</Button>
          </SpaceBetween>
        </Box>
      }
    >
      <SpaceBetween size="l">
        <Inspector mode="decrypt" events={events} error={error} />
        {plain && isText(obj.content_type, obj.object_key) && (
          <FormField label="Decrypted in your browser">
            <pre className="plain-preview">{utf8Decoder.decode(plain.subarray(0, 20000))}</pre>
          </FormField>
        )}
      </SpaceBetween>
    </Modal>
  );
}

// ------------------------------------------------------------------------------------------ raw
function entropy(bytes: Uint8Array): number {
  const counts = new Array(256).fill(0);
  bytes.forEach((b) => counts[b]++);
  return -counts.reduce((s, c) => (c ? s + (c / bytes.length) * Math.log2(c / bytes.length) : s), 0);
}

function RawModal({ bucket, obj, onClose }: { bucket: string; obj: StoredObject; onClose: () => void }) {
  const { token } = useAuthed();
  const body = useLoad(() => vault.body(token, bucket, obj.id).then((r) => r.data), [obj.id]);
  const env = obj.envelope;
  const wrapped = b64.decode(env.ciphertext_blob);

  return (
    <Modal visible size="large" onDismiss={onClose} header={`Raw view: ${obj.object_key}`} footer={<Box float="right"><Button variant="primary" onClick={onClose}>Close</Button></Box>}>
      <SpaceBetween size="l">
        <Alert type="info" header="This is everything the storage server holds for this object">
          Nothing below can decrypt it. The data key is wrapped under a CMK that only exists inside Stratus KMS.
        </Alert>
        <KeyValuePairs
          columns={3}
          items={[
            { label: 'Stored bytes', value: `${obj.stored_size} (plaintext + 16-byte GCM tag)` },
            { label: 'Byte entropy', value: body.data ? `${entropy(body.data).toFixed(2)} bits/byte` : '…' },
            { label: 'Ciphertext SHA-256', value: <Box variant="code">{obj.ciphertext_sha256.slice(0, 24)}…</Box> },
            { label: 'Algorithm', value: 'AES-256-GCM' },
            { label: 'IV (96-bit)', value: <Box variant="code">{hex(b64.decode(env.iv))}</Box> },
            { label: 'Wrapping', value: `${env.wrap_algorithm === 'AES_KW' ? 'AES Key Wrap' : 'RSA-2048-OAEP'}, key v${env.kms_key_version}` },
          ]}
        />
        <FormField label={<>Ciphertext (first 256 bytes)</>}>
          <pre className="raw-hex">{body.data ? hex(body.data, 256) : 'Loading…'}</pre>
        </FormField>
        <FormField label={<><Term k="WRAPPED">Wrapped data key</Term> ({wrapped.length} bytes)</>}>
          <pre className="raw-hex">{hex(wrapped)}</pre>
        </FormField>
        <FormField label={<Term k="CONTEXT">Encryption context (also the GCM AAD)</Term>}>
          <pre className="raw-hex">{JSON.stringify(env.encryption_context, null, 2)}</pre>
        </FormField>
      </SpaceBetween>
    </Modal>
  );
}
