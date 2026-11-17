import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Badge from '@cloudscape-design/components/badge';
import type { Cmk, KeyState, WrapAlgorithm } from '../lib/api';

export function KeyStatus({ state }: { state: KeyState }) {
  switch (state) {
    case 'Enabled':
      return <StatusIndicator type="success">Enabled</StatusIndicator>;
    case 'Disabled':
      return <StatusIndicator type="stopped">Disabled</StatusIndicator>;
    case 'PendingDeletion':
      return <StatusIndicator type="warning">Pending deletion</StatusIndicator>;
    default:
      return <StatusIndicator type="error">Deleted</StatusIndicator>;
  }
}

export function algoLabel(a: WrapAlgorithm) {
  return a === 'AES_KW' ? 'AES-256 Key Wrap' : 'RSA-2048-OAEP';
}

export function RoleBadge({ role }: { role: Cmk['my_role'] }) {
  if (!role) return <Badge color="grey">No access</Badge>;
  return <Badge color={role === 'admin' ? 'blue' : 'green'}>{role === 'admin' ? 'Admin' : 'User'}</Badge>;
}

export function keySrn(k: Pick<Cmk, 'key_id'>, tenant: string) {
  return `srn:stratus:kms:pk-north-1:${tenant}:key/${k.key_id}`;
}
