import { useState } from 'react';
import { useParams } from 'react-router-dom';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import Modal from '@cloudscape-design/components/modal';
import RadioGroup from '@cloudscape-design/components/radio-group';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import Tabs from '@cloudscape-design/components/tabs';
import { kms, type Cmk } from '../lib/api';
import { errorText, useAuthed } from '../lib/session';
import { fmtDate, timeAgo, useLoad } from '../lib/useLoad';
import { Hot, InfoLink, usePage } from '../console/Shell';
import { algoLabel, KeyStatus, keySrn } from '../components/KeyBits';
import Term from '../components/Term';

export default function KeyDetail() {
  const { keyId = '' } = useParams();
  const { token, user, notify } = useAuthed();
  const { data: key, error, setData, reload } = useLoad(() => kms.key(token, keyId), [token, keyId]);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);

  usePage({
    help: 'key',
    crumbs: [
      { text: 'KMS', href: '/console/kms/keys' },
      { text: 'Customer managed keys', href: '/console/kms/keys' },
      { text: key?.alias ?? '…', href: '#' },
    ],
  });

  if (error) return <Alert type="error" header="Could not load key">{error}</Alert>;
  if (!key) return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;

  const isAdmin = key.my_role === 'admin';
  const act = async (label: string, fn: () => Promise<Cmk>, done: (k: Cmk) => string) => {
    setBusy(true);
    try {
      const k = await fn();
      setData(k);
      notify({ type: 'success', content: done(k) });
    } catch (e) {
      notify({ type: 'error', header: `${label} failed`, content: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          info={<InfoLink topic="key" />}
          description={key.description || 'Customer managed key'}
          actions={
            <Hot id="key-actions" side="left">
              <ButtonDropdown
                loading={busy}
                disabled={!isAdmin}
                disabledReason="Only key admins can change this key"
                items={[
                  { id: 'rotate', text: 'Rotate now', disabled: key.state !== 'Enabled', description: 'Create a new primary version' },
                  key.state === 'Disabled'
                    ? { id: 'enable', text: 'Enable' }
                    : { id: 'disable', text: 'Disable', disabled: key.state !== 'Enabled' },
                  key.state === 'PendingDeletion'
                    ? { id: 'cancel', text: 'Cancel key deletion' }
                    : { id: 'delete', text: 'Schedule key deletion', disabled: key.state === 'Deleted' },
                ]}
                onItemClick={(e) => {
                  const id = e.detail.id;
                  if (id === 'rotate')
                    act('Rotation', () => kms.rotate(token, key.key_id), (k) => `Rotated. v${k.primary_version} is now primary; older versions still decrypt.`);
                  if (id === 'disable')
                    act('Disable', () => kms.disable(token, key.key_id), () => 'Key disabled. Every encrypt and decrypt request is now refused.');
                  if (id === 'enable') act('Enable', () => kms.enable(token, key.key_id), () => 'Key enabled.');
                  if (id === 'cancel')
                    act('Cancel deletion', () => kms.cancelDeletion(token, key.key_id), () => 'Deletion cancelled. The key is disabled until you enable it.');
                  if (id === 'delete') setDeleting(true);
                }}
              >
                Key actions
              </ButtonDropdown>
            </Hot>
          }
        >
          {key.alias}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {key.state === 'PendingDeletion' && (
          <Alert
            type="warning"
            header={`Key material will be destroyed ${timeAgo(key.deletion_date)}`}
            action={isAdmin && <Button onClick={() => act('Cancel deletion', () => kms.cancelDeletion(token, key.key_id), () => 'Deletion cancelled.')}>Cancel deletion</Button>}
          >
            While pending, the key cannot be used. After {fmtDate(key.deletion_date)} every object encrypted under it becomes unreadable.
          </Alert>
        )}
        {key.state === 'Deleted' && (
          <Alert type="error" header="Key material destroyed">
            This key has been <Term k="SHRED">crypto-shredded</Term>. Ciphertext protected by it still exists in the Vault but can never be decrypted.
          </Alert>
        )}

        <Container header={<Header variant="h2">General configuration</Header>}>
          <KeyValuePairs
            columns={3}
            items={[
              { label: 'Alias', value: key.alias },
              { label: 'Status', value: <KeyStatus state={key.state} /> },
              { label: 'Wrapping algorithm', value: algoLabel(key.algorithm) },
              {
                label: 'SRN',
                value: (
                  <CopyToClipboard
                    variant="inline"
                    textToCopy={keySrn(key, user.tenant_id)}
                    copySuccessText="SRN copied"
                    copyErrorText="Could not copy"
                  />
                ),
              },
              { label: 'Primary version', value: `v${key.primary_version} of ${key.versions.length}` },
              { label: 'Sealed under', value: <><Term k="KEK">Root KEK</Term> <Box variant="code">{key.root_key_id}</Box></> },
              { label: 'Created', value: `${fmtDate(key.created_at)} by ${key.created_by}` },
              { label: 'Your access', value: key.my_role ? (key.my_role === 'admin' ? 'Admin: use and manage' : 'User: encrypt and decrypt') : 'None' },
              { label: 'Key ID', value: <Box variant="code">{key.key_id}</Box> },
            ]}
          />
        </Container>

        <Tabs
          tabs={[
            { id: 'hierarchy', label: 'Key hierarchy', content: <Hierarchy k={key} /> },
            { id: 'versions', label: `Versions (${key.versions.length})`, content: <Versions k={key} /> },
            { id: 'access', label: `Access (${key.access.length})`, content: <Access k={key} onChange={setData} reload={reload} /> },
          ]}
        />
      </SpaceBetween>

      <DeleteModal k={key} visible={deleting} onClose={() => setDeleting(false)} onDone={(k) => { setDeleting(false); setData(k); }} />
    </ContentLayout>
  );
}

function Hierarchy({ k }: { k: Cmk }) {
  return (
    <Container>
      <div className="hier">
        <div className="hier-row root">
          <div className="hier-tag">Tier 1</div>
          <div>
            <strong><Term k="KEK">Root KEK</Term></strong> <Box variant="code">{k.root_key_id}</Box>
            <div className="hier-sub">AES-256, held only in the KMS process. Wraps CMK material with AES Key Wrap (RFC 3394).</div>
          </div>
        </div>
        <div className="hier-row cmk">
          <div className="hier-tag">Tier 2</div>
          <div>
            <strong><Term k="CMK">{k.alias}</Term></strong>
            <div className="hier-versions">
              {k.versions.map((v) => (
                <span key={v.version} className={`hier-v ${v.status === 'Primary' ? 'primary' : ''} ${v.status === 'Destroyed' ? 'gone' : ''}`}>
                  v{v.version}
                </span>
              ))}
            </div>
            <div className="hier-sub">
              Each version is a separate key. Wraps data keys with {algoLabel(k.algorithm)}, and binds them to the <Term k="CONTEXT">encryption context</Term> with HMAC-SHA256.
            </div>
          </div>
        </div>
        <div className="hier-row dek">
          <div className="hier-tag">Tier 3</div>
          <div>
            <strong><Term k="DEK">Data keys</Term></strong>
            <div className="hier-sub">One per object, generated on request. The plaintext copy lives in your browser for milliseconds; the wrapped copy is stored next to the ciphertext in the Vault.</div>
          </div>
        </div>
      </div>
    </Container>
  );
}

function Versions({ k }: { k: Cmk }) {
  return (
    <Table
      variant="container"
      header={<Header description="Rotation adds a version. Only the primary encrypts; older versions still decrypt existing objects.">Key versions</Header>}
      items={[...k.versions].reverse()}
      trackBy="version"
      columnDefinitions={[
        { id: 'v', header: 'Version', cell: (v) => `v${v.version}` },
        {
          id: 's',
          header: 'Status',
          cell: (v) =>
            v.status === 'Primary' ? (
              <StatusIndicator type="success">Primary</StatusIndicator>
            ) : v.status === 'Destroyed' ? (
              <StatusIndicator type="error">Destroyed</StatusIndicator>
            ) : (
              <StatusIndicator type="info">Decrypt only</StatusIndicator>
            ),
        },
        { id: 'c', header: 'Created', cell: (v) => fmtDate(v.created_at) },
        {
          id: 'pub',
          header: 'Public key',
          cell: (v) => (v.public_key_pem ? <Box variant="code">{v.public_key_pem.split('\n')[1]?.slice(0, 24)}…</Box> : '-'),
        },
      ]}
    />
  );
}

function Access({ k, onChange, reload }: { k: Cmk; onChange: (k: Cmk) => void; reload: () => void }) {
  const { token, notify } = useAuthed();
  const { data: users } = useLoad(() => kms.users(token), [token]);
  const [who, setWho] = useState<string | null>(null);
  const [role, setRole] = useState<'user' | 'admin'>('user');
  const isAdmin = k.my_role === 'admin';

  const update = async (username: string, r: 'user' | 'admin' | null) => {
    try {
      onChange(await kms.setAccess(token, k.key_id, username, r));
      notify({
        type: 'success',
        content: r ? `${username} is now a key ${r}.` : `Revoked ${username}'s access. Their next request will be denied.`,
      });
    } catch (e) {
      notify({ type: 'error', content: errorText(e) });
      reload();
    }
  };

  const candidates = (users ?? []).filter((u) => !k.access.some((a) => a.username === u.username));

  return (
    <Table
      variant="container"
      header={
        <Header
          description="Only users on this list can use the key. Users from other tenants can never be added."
          actions={
            isAdmin && (
              <SpaceBetween direction="horizontal" size="xs">
                <Select
                  placeholder="Add a user"
                  selectedOption={who ? { value: who, label: who } : null}
                  options={candidates.map((u) => ({ value: u.username, label: u.display_name, description: u.username }))}
                  onChange={(e) => setWho(e.detail.selectedOption.value ?? null)}
                  empty="Everyone in your tenant already has access"
                />
                <Select
                  selectedOption={{ value: role, label: role === 'user' ? 'User' : 'Admin' }}
                  options={[{ value: 'user', label: 'User' }, { value: 'admin', label: 'Admin' }]}
                  onChange={(e) => setRole(e.detail.selectedOption.value as 'user' | 'admin')}
                />
                <Button disabled={!who} onClick={() => who && update(who, role).then(() => setWho(null))}>
                  Grant
                </Button>
              </SpaceBetween>
            )
          }
        >
          Access list
        </Header>
      }
      items={k.access}
      trackBy="username"
      columnDefinitions={[
        { id: 'u', header: 'User', cell: (a) => `${a.display_name} (${a.username})` },
        { id: 'r', header: 'Role', cell: (a) => (a.role === 'admin' ? 'Admin: use and manage' : 'User: encrypt and decrypt') },
        {
          id: 'x',
          header: '',
          cell: (a) =>
            isAdmin && a.role !== 'admin' ? (
              <Button variant="inline-link" onClick={() => update(a.username, null)}>
                Revoke
              </Button>
            ) : null,
        },
      ]}
    />
  );
}

function DeleteModal({ k, visible, onClose, onDone }: { k: Cmk; visible: boolean; onClose: () => void; onDone: (k: Cmk) => void }) {
  const { token, notify } = useAuthed();
  const [minutes, setMinutes] = useState('2');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    try {
      const res = await kms.scheduleDeletion(token, k.key_id, Number(minutes));
      notify({
        type: res.state === 'Deleted' ? 'warning' : 'info',
        content: res.state === 'Deleted' ? `${k.alias} destroyed. Its objects are now crypto-shredded.` : `${k.alias} scheduled for deletion.`,
      });
      setConfirm('');
      onDone(res);
    } catch (e) {
      notify({ type: 'error', content: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      visible={visible}
      onDismiss={onClose}
      header="Schedule key deletion"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onClose}>Cancel</Button>
            <Button variant="primary" loading={busy} disabled={confirm !== k.alias} onClick={submit}>
              Schedule deletion
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      <SpaceBetween size="m">
        <Alert type="warning">
          When the waiting period ends, every version of this key is destroyed. Objects encrypted under it can never be decrypted again. This is <Term k="SHRED">crypto-shredding</Term>.
        </Alert>
        <FormField label="Waiting period" description="Production KMSs enforce 7-30 days. Demo mode also allows shorter windows.">
          <RadioGroup
            value={minutes}
            onChange={(e) => setMinutes(e.detail.value)}
            items={[
              { value: '0', label: 'Immediately', description: 'Demo only' },
              { value: '2', label: '2 minutes', description: 'Demo only: time to show the pending state' },
              { value: String(7 * 24 * 60), label: '7 days' },
              { value: String(30 * 24 * 60), label: '30 days' },
            ]}
          />
        </FormField>
        <FormField label={`To confirm, type ${k.alias}`}>
          <Input value={confirm} onChange={(e) => setConfirm(e.detail.value)} placeholder={k.alias} />
        </FormField>
      </SpaceBetween>
    </Modal>
  );
}
