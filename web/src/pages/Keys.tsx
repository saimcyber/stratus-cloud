import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Link from '@cloudscape-design/components/link';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import Textarea from '@cloudscape-design/components/textarea';
import Tiles from '@cloudscape-design/components/tiles';
import { kms, type Cmk, type WrapAlgorithm } from '../lib/api';
import { errorText, useAuthed } from '../lib/session';
import { timeAgo, useLoad } from '../lib/useLoad';
import { Hot, InfoLink, usePage } from '../console/Shell';
import { algoLabel, KeyStatus, RoleBadge } from '../components/KeyBits';
import Term from '../components/Term';

export default function Keys() {
  usePage({ help: 'keys', crumbs: [{ text: 'KMS', href: '/console/kms/keys' }, { text: 'Customer managed keys', href: '#' }] });
  const { token, notify } = useAuthed();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useLoad(() => kms.keys(token), [token]);
  const [filter, setFilter] = useState('');
  const [creating, setCreating] = useState(false);

  const keys = (data ?? []).filter((k) => `${k.alias} ${k.key_id} ${k.description}`.toLowerCase().includes(filter.toLowerCase()));

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          info={<InfoLink topic="keys" />}
          description={
            <>
              Keys that wrap your <Term k="DEK">data keys</Term>. Their material is sealed under the{' '}
              <Term k="KEK">Root KEK</Term> and never leaves Stratus KMS.
            </>
          }
        >
          Customer managed keys
        </Header>
      }
    >
      <Hot id="keys-table">
        <Table<Cmk>
          loading={loading && !data}
          loadingText="Loading keys"
          items={keys}
          trackBy="key_id"
          variant="full-page"
          stickyHeader
          header={
            <Header
              counter={data ? `(${data.length})` : undefined}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button iconName="refresh" ariaLabel="Refresh" onClick={reload} />
                  <Button variant="primary" onClick={() => setCreating(true)}>
                    Create key
                  </Button>
                </SpaceBetween>
              }
            >
              Keys
            </Header>
          }
          filter={
            <TextFilter filteringText={filter} onChange={(e) => setFilter(e.detail.filteringText)} filteringPlaceholder="Find keys" />
          }
          empty={
            <Box textAlign="center" color="inherit" padding="l">
              {error ? <Box color="text-status-error">{error}</Box> : 'No keys yet.'}
            </Box>
          }
          columnDefinitions={[
            {
              id: 'alias',
              header: 'Alias',
              cell: (k) => (
                <Link
                  href={`/console/kms/keys/${k.key_id}`}
                  onFollow={(e) => {
                    e.preventDefault();
                    navigate(`/console/kms/keys/${k.key_id}`);
                  }}
                >
                  {k.alias}
                </Link>
              ),
              isRowHeader: true,
            },
            { id: 'id', header: 'Key ID', cell: (k) => <Box variant="code">{k.key_id.slice(0, 8)}…</Box> },
            { id: 'status', header: 'Status', cell: (k) => <KeyStatus state={k.state} /> },
            { id: 'algo', header: 'Wrapping', cell: (k) => algoLabel(k.algorithm) },
            { id: 'version', header: 'Primary version', cell: (k) => `v${k.primary_version}` },
            { id: 'access', header: 'Your access', cell: (k) => <RoleBadge role={k.my_role} /> },
            { id: 'created', header: 'Created', cell: (k) => timeAgo(k.created_at) },
          ]}
        />
      </Hot>
      <CreateKeyModal
        visible={creating}
        onClose={() => setCreating(false)}
        onCreated={(k) => {
          setCreating(false);
          notify({ type: 'success', content: `Created ${k.alias}. You are its admin.` });
          navigate(`/console/kms/keys/${k.key_id}`);
        }}
      />
    </ContentLayout>
  );
}

function CreateKeyModal({ visible, onClose, onCreated }: { visible: boolean; onClose: () => void; onCreated: (k: Cmk) => void }) {
  const { token } = useAuthed();
  const [alias, setAlias] = useState('');
  const [description, setDescription] = useState('');
  const [algorithm, setAlgorithm] = useState<WrapAlgorithm>('AES_KW');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const k = await kms.createKey(token, alias, description, algorithm);
      setAlias('');
      setDescription('');
      onCreated(k);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal visible={visible} onDismiss={onClose} header="Create customer managed key" size="medium">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Form
          errorText={error}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" formAction="none" onClick={onClose}>
                Cancel
              </Button>
              <Button variant="primary" loading={busy} disabled={!alias.trim()}>
                Create key
              </Button>
            </SpaceBetween>
          }
        >
          <SpaceBetween size="l">
            <FormField label="Alias" description="A friendly name, unique in your tenant." constraintText="Prefixed with alias/ automatically.">
              <Input value={alias} onChange={(e) => setAlias(e.detail.value)} placeholder="lab-results" autoFocus />
            </FormField>
            <FormField label="Description - optional">
              <Textarea value={description} onChange={(e) => setDescription(e.detail.value)} rows={2} />
            </FormField>
            <FormField label="How data keys are wrapped">
              <Tiles
                value={algorithm}
                onChange={(e) => setAlgorithm(e.detail.value as WrapAlgorithm)}
                columns={2}
                items={[
                  {
                    value: 'AES_KW',
                    label: 'AES-256 Key Wrap',
                    description: 'RFC 3394. Symmetric and fast. Recommended.',
                  },
                  {
                    value: 'RSA_2048_OAEP',
                    label: 'RSA-2048-OAEP',
                    description: 'Asymmetric, SHA-256. Slower, but the public key can wrap offline.',
                  },
                ]}
              />
            </FormField>
          </SpaceBetween>
        </Form>
      </form>
    </Modal>
  );
}
