import { useEffect, useState } from 'react';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SegmentedControl from '@cloudscape-design/components/segmented-control';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import Toggle from '@cloudscape-design/components/toggle';
import { kms, vault, type AuditEvent } from '../lib/api';
import { useAuthed } from '../lib/session';
import { fmtDate, useLoad } from '../lib/useLoad';
import { InfoLink, usePage } from '../console/Shell';
import { Outcome } from './Home';

export default function Activity() {
  usePage({ help: 'activity', crumbs: [{ text: 'Security', href: '#' }, { text: 'Activity', href: '#' }] });
  const { token } = useAuthed();
  const { data, loading, reload } = useLoad(async () => {
    const [a, b] = await Promise.all([kms.audit(token), vault.audit(token)]);
    return [...a, ...b].sort((x, y) => y.at.localeCompare(x.at));
  }, [token]);
  const [service, setService] = useState('all');
  const [deniedOnly, setDeniedOnly] = useState(false);
  const [filter, setFilter] = useState('');
  const [live, setLive] = useState(true);

  useEffect(() => {
    if (!live) return;
    const t = setInterval(reload, 5000);
    return () => clearInterval(t);
  }, [live, reload]);

  const items = (data ?? []).filter(
    (e) =>
      (service === 'all' || e.service === service) &&
      (!deniedOnly || !['Success', 'Simulated'].includes(e.outcome)) &&
      `${e.action} ${e.actor} ${e.detail} ${e.resource ?? ''} ${e.outcome}`.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <ContentLayout
      header={
        <Header variant="h1" info={<InfoLink topic="activity" />} description="Every call to the KMS and the Vault for your tenant, including the ones that were refused.">
          Activity
        </Header>
      }
    >
      <Table<AuditEvent>
        variant="full-page"
        loading={loading && !data}
        loadingText="Loading events"
        items={items}
        trackBy={(e) => `${e.service}-${e.id}`}
        wrapLines
        header={
          <Header
            counter={`(${items.length})`}
            actions={
              <SpaceBetween direction="horizontal" size="s" alignItems="center">
                <Toggle checked={live} onChange={(e) => setLive(e.detail.checked)}>Live</Toggle>
                <Button iconName="refresh" ariaLabel="Refresh" onClick={reload} />
              </SpaceBetween>
            }
          >
            Events
          </Header>
        }
        filter={
          <SpaceBetween direction="horizontal" size="s" alignItems="center">
            <TextFilter filteringText={filter} onChange={(e) => setFilter(e.detail.filteringText)} filteringPlaceholder="Filter events" />
            <SegmentedControl
              selectedId={service}
              onChange={(e) => setService(e.detail.selectedId)}
              options={[{ id: 'all', text: 'All' }, { id: 'kms', text: 'KMS' }, { id: 'vault', text: 'Vault' }]}
              label="Service"
            />
            <Toggle checked={deniedOnly} onChange={(e) => setDeniedOnly(e.detail.checked)}>Refused only</Toggle>
          </SpaceBetween>
        }
        empty={<Box textAlign="center" padding="l">No matching events</Box>}
        columnDefinitions={[
          { id: 'at', header: 'Time', cell: (e) => fmtDate(e.at), width: 190 },
          { id: 'svc', header: 'Service', cell: (e) => (e.service === 'kms' ? 'KMS' : 'Vault'), width: 90 },
          { id: 'action', header: 'Action', cell: (e) => e.action },
          { id: 'actor', header: 'User', cell: (e) => e.actor },
          { id: 'outcome', header: 'Outcome', cell: (e) => <Outcome e={e} /> },
          {
            id: 'detail',
            header: 'Detail',
            cell: (e) => (
              <Box fontSize="body-s" color="text-body-secondary">
                {[e.resource, e.key_id ? `key ${e.key_id.slice(0, 8)}…` : null, e.detail].filter(Boolean).join(' · ')}
              </Box>
            ),
          },
        ]}
      />
    </ContentLayout>
  );
}
