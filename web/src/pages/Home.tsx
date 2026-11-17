import { useNavigate } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Grid from '@cloudscape-design/components/grid';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import { kms, vault, type AuditEvent } from '../lib/api';
import { useAuthed } from '../lib/session';
import { timeAgo, useLoad } from '../lib/useLoad';
import { InfoLink, usePage, useShell } from '../console/Shell';
import Term from '../components/Term';

async function loadOverview(token: string) {
  const [keys, buckets, kAudit, vAudit] = await Promise.all([kms.keys(token), vault.buckets(token), kms.audit(token), vault.audit(token)]);
  const objectLists = await Promise.all(buckets.map((b) => vault.objects(token, b.name)));
  const primary = new Map(keys.map((k) => [k.key_id, k.primary_version]));
  const objects = objectLists.flat();
  const stale = objects.filter((o) => (primary.get(o.envelope.kms_key_id) ?? 0) > o.envelope.kms_key_version).length;
  const events = [...kAudit, ...vAudit].sort((a, b) => b.at.localeCompare(a.at)).slice(0, 6);
  return { keys, buckets, objects: objects.length, stale, events };
}

export function Outcome({ e }: { e: AuditEvent }) {
  if (e.outcome === 'Success') return <StatusIndicator type="success">Success</StatusIndicator>;
  if (e.outcome === 'Simulated') return <StatusIndicator type="info">Simulated</StatusIndicator>;
  return <StatusIndicator type="error">{e.outcome}</StatusIndicator>;
}

export default function Home() {
  usePage({ help: 'home', crumbs: [{ text: 'Dashboard', href: '#' }] });
  const { token, user } = useAuthed();
  const { openTutorial } = useShell();
  const navigate = useNavigate();
  const { data, loading } = useLoad(() => loadOverview(token), [token]);

  const stat = (label: string, value: number | undefined, href?: string) => (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="awsui-value-large">
        {href ? (
          <Link variant="awsui-value-large" href={href} onFollow={(e) => { e.preventDefault(); navigate(href); }}>
            {loading ? '…' : value}
          </Link>
        ) : loading ? '…' : value}
      </Box>
    </div>
  );

  return (
    <ContentLayout
      header={
        <Header variant="h1" info={<InfoLink topic="home" />} description={`${user.tenant_name} · ${user.role === 'admin' ? 'Tenant admin' : 'Member'} · pk-north-1`}>
          Welcome back, {user.display_name}
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Overview</Header>}>
          <ColumnLayout columns={4} variant="text-grid" minColumnWidth={140}>
            {stat('Customer managed keys', data?.keys.length, '/console/kms/keys')}
            {stat('Buckets', data?.buckets.length, '/console/vault/buckets')}
            {stat('Encrypted objects', data?.objects)}
            {stat('Waiting for re-wrap', data?.stale)}
          </ColumnLayout>
        </Container>

        <Grid gridDefinition={[{ colspan: { default: 12, l: 8 } }, { colspan: { default: 12, l: 4 } }]}>
          <Container header={<Header variant="h2" description="Who can see what, by design.">Trust boundaries</Header>} fitHeight>
            <div className="tb">
              <div className="tb-col">
                <div className="tb-title">Your browser</div>
                <div className="tb-sees">Sees the file and, for milliseconds, the <Term k="DEK">data key</Term>.</div>
                <div className="tb-does">Encrypts with <Term k="GCM">AES-256-GCM</Term>, then <Term k="ZEROIZE">wipes the key</Term>.</div>
              </div>
              <div className="tb-col">
                <div className="tb-title">Stratus KMS</div>
                <div className="tb-sees">Sees 32-byte keys and <Term k="CONTEXT">labels</Term>. Never your file.</div>
                <div className="tb-does">Holds the <Term k="KEK">Root KEK</Term> and your <Term k="CMK">CMKs</Term>; checks access on every call.</div>
              </div>
              <div className="tb-col untrusted">
                <div className="tb-title">Stratus Vault <span>untrusted</span></div>
                <div className="tb-sees">Sees ciphertext and <Term k="WRAPPED">wrapped keys</Term>. Nothing it holds can decrypt.</div>
                <div className="tb-does">No KMS credentials, no signing keys. Safe to compromise.</div>
              </div>
            </div>
          </Container>
          <Container header={<Header variant="h2">Get started</Header>} fitHeight>
            <SpaceBetween size="s">
              <Button fullWidth variant="primary" iconName="suggestions" onClick={openTutorial}>Start the walkthrough</Button>
              <Button fullWidth onClick={() => navigate('/console/vault/buckets/acme-patient-records')} disabled={user.tenant_id !== 'acme-health'}>
                Encrypt a file
              </Button>
              <Button fullWidth onClick={() => navigate('/console/lab')}>Try to break in</Button>
              <Button fullWidth onClick={() => navigate('/console/tradeoffs')}>Measure the trade-offs</Button>
            </SpaceBetween>
          </Container>
        </Grid>

        <Table<AuditEvent>
          header={
            <Header variant="h2" actions={<Button onClick={() => navigate('/console/activity')}>View all activity</Button>}>
              Recent activity
            </Header>
          }
          loading={loading}
          loadingText="Loading activity"
          items={data?.events ?? []}
          trackBy={(e) => `${e.service}-${e.id}`}
          columnDefinitions={[
            { id: 'when', header: 'When', cell: (e) => timeAgo(e.at) },
            { id: 'svc', header: 'Service', cell: (e) => (e.service === 'kms' ? 'KMS' : 'Vault') },
            { id: 'action', header: 'Action', cell: (e) => e.action },
            { id: 'actor', header: 'User', cell: (e) => e.actor },
            { id: 'outcome', header: 'Outcome', cell: (e) => <Outcome e={e} /> },
          ]}
          empty={<Box textAlign="center">No activity yet</Box>}
        />
      </SpaceBetween>
    </ContentLayout>
  );
}
