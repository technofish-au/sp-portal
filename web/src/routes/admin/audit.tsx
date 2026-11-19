import { Alert, Button, Card, Code, Group, Loader, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { api, type AuditEntry } from '../../api';
import { AdminNav } from '../../adminNav';
import { RequireStaff } from '../../auth';
import { formatTime } from '../../ui';

const PAGE = 50;

function AdminAuditPage() {
  const [orgId, setOrgId] = useState('');
  const [appliedOrg, setAppliedOrg] = useState('');
  const [offset, setOffset] = useState(0);

  const entries = useQuery({
    queryKey: ['admin-audit', appliedOrg, offset],
    queryFn: () =>
      api<{ entries: AuditEntry[] }>(
        `/v1/admin/audit-log?limit=${PAGE}&offset=${offset}${
          appliedOrg ? `&org_id=${appliedOrg}` : ''
        }`,
      ),
  });

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>Audit log</Title>
        <AdminNav />
      </Group>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setOffset(0);
          setAppliedOrg(orgId.trim());
        }}
      >
        <TextInput
          label="Filter by organisation id"
          placeholder="empty = all organisations"
          value={orgId}
          onChange={(e) => setOrgId(e.currentTarget.value)}
          maw={480}
        />
      </form>
      {entries.isLoading && <Loader />}
      {entries.isError && <Alert color="red">Failed to load audit entries.</Alert>}
      {entries.data && (
        <Card withBorder padding="0">
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>When</Table.Th>
                <Table.Th>Actor</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Target</Table.Th>
                <Table.Th>IP</Table.Th>
                <Table.Th>Detail</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {entries.data.entries.map((e) => (
                <Table.Tr key={e.id}>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}>{formatTime(e.created_at)}</Table.Td>
                  <Table.Td>{e.actor_email || '—'}</Table.Td>
                  <Table.Td>
                    <Code>{e.action}</Code>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {e.target_type}:{e.target_id.slice(0, 8)}
                    </Text>
                  </Table.Td>
                  <Table.Td>{e.ip || '—'}</Table.Td>
                  <Table.Td>
                    {e.detail ? (
                      <Code>{JSON.stringify(e.detail)}</Code>
                    ) : (
                      <Text c="dimmed">—</Text>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
              {entries.data.entries.length === 0 && (
                <Table.Tr>
                  <Table.Td c="dimmed">No entries</Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Card>
      )}
      <Group>
        <Button
          variant="default"
          disabled={offset === 0}
          onClick={() => setOffset((o) => Math.max(0, o - PAGE))}
        >
          Newer
        </Button>
        <Button
          variant="default"
          disabled={(entries.data?.entries.length ?? 0) < PAGE}
          onClick={() => setOffset((o) => o + PAGE)}
        >
          Older
        </Button>
      </Group>
    </Stack>
  );
}

export const Route = createFileRoute('/admin/audit')({
  component: () => (
    <RequireStaff>
      <AdminAuditPage />
    </RequireStaff>
  ),
});
