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
import { vault, type Bucket } from '../lib/api';
import { formatBytes } from '../lib/envelope';
import { errorText, useAuthed } from '../lib/session';
import { timeAgo, useLoad } from '../lib/useLoad';
import { Hot, InfoLink, usePage } from '../console/Shell';

export default function Buckets() {
  usePage({ help: 'buckets', crumbs: [{ text: 'Vault', href: '/console/vault/buckets' }, { text: 'Buckets', href: '#' }] });
  const { token, notify } = useAuthed();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useLoad(() => vault.buckets(token), [token]);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setFormError(null);
    try {
      await vault.createBucket(token, name.trim());
      notify({ type: 'success', content: `Bucket ${name} created.` });
      setCreating(false);
      setName('');
      reload();
    } catch (e) {
      setFormError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <ContentLayout
      header={
        <Header variant="h1" info={<InfoLink topic="buckets" />} description="Object storage that only ever receives ciphertext. Every object is sealed in your browser first.">
          Buckets
        </Header>
      }
    >
      <Table<Bucket>
        variant="full-page"
        loading={loading && !data}
        loadingText="Loading buckets"
        items={data ?? []}
        trackBy="name"
        header={
          <Header
            counter={data ? `(${data.length})` : undefined}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button iconName="refresh" ariaLabel="Refresh" onClick={reload} />
                <Button variant="primary" onClick={() => setCreating(true)}>Create bucket</Button>
              </SpaceBetween>
            }
          >
            Buckets
          </Header>
        }
        empty={<Box textAlign="center" padding="l">{error ?? 'No buckets yet.'}</Box>}
        columnDefinitions={[
          {
            id: 'name',
            header: 'Name',
            isRowHeader: true,
            cell: (b) => {
              const link = (
                <Link href={`/console/vault/buckets/${b.name}`} onFollow={(e) => { e.preventDefault(); navigate(`/console/vault/buckets/${b.name}`); }}>
                  {b.name}
                </Link>
              );
              return b.name === 'acme-patient-records' ? <Hot id="bucket-link">{link}</Hot> : link;
            },
          },
          { id: 'enc', header: 'Default encryption', cell: () => 'Client-side envelope (AES-256-GCM)' },
          { id: 'objects', header: 'Objects', cell: (b) => b.object_count },
          { id: 'size', header: 'Plaintext size', cell: (b) => formatBytes(b.total_bytes) },
          { id: 'created', header: 'Created', cell: (b) => timeAgo(b.created_at) },
        ]}
      />
      <Modal visible={creating} onDismiss={() => setCreating(false)} header="Create bucket">
        <form onSubmit={(e) => { e.preventDefault(); create(); }}>
          <Form
            errorText={formError}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" formAction="none" onClick={() => setCreating(false)}>Cancel</Button>
                <Button variant="primary" loading={busy} disabled={!name.trim()}>Create bucket</Button>
              </SpaceBetween>
            }
          >
            <FormField label="Bucket name" constraintText="3-63 lowercase letters, numbers and hyphens. Unique across Stratus.">
              <Input value={name} onChange={(e) => setName(e.detail.value.toLowerCase())} placeholder="acme-lab-results" autoFocus />
            </FormField>
          </Form>
        </form>
      </Modal>
    </ContentLayout>
  );
}
