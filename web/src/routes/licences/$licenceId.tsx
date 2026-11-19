import { Alert, Badge, Card, Group, Loader, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { api, type Instance, type Licence } from '../../api';
import { RequireAuth } from '../../auth';
import { formatTime, STATUS_COLOR } from '../../ui';

interface LicenceDetail {
  licence: Licence;
  instances: Instance[];
}

function LicenceDetailPage() {
  const { licenceId } = Route.useParams();
  const q = useQuery({
    queryKey: ['licence', licenceId],
    queryFn: () => api<LicenceDetail>(`/v1/licences/${licenceId}`),
  });

  if (q.isLoading) return <Loader mt="xl" />;
  if (q.isError) return <Alert color="red">Failed to load the licence.</Alert>;
  const { licence: lic, instances } = q.data!;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>Licence</Title>
        <Badge size="lg" color={STATUS_COLOR[lic.status] ?? 'gray'}>
          {lic.status}
        </Badge>
      </Group>

      <Card withBorder maw={720}>
        <Stack gap="xs">
          <Group justify="space-between">
            <Text c="dimmed">Key</Text>
            <Text ff="monospace">{lic.licence_key}</Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Kind / plan</Text>
            <Text>
              {lic.kind} / {lic.plan}
            </Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Seats</Text>
            <Text>
              {lic.seats_used} of {lic.max_instances} in use
            </Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Issued</Text>
            <Text>{formatTime(lic.issued_at)}</Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Expires</Text>
            <Text>{lic.expires_at ? formatTime(lic.expires_at) : 'never'}</Text>
          </Group>
          {lic.revoked_at && (
            <Group justify="space-between">
              <Text c="dimmed">Revoked</Text>
              <Text c="red">{formatTime(lic.revoked_at)}</Text>
            </Group>
          )}
          <Group justify="space-between">
            <Text c="dimmed">Licence document</Text>
            <Group gap="xs">
              <Badge variant="light" color={lic.doc_issued ? 'blue' : 'gray'}>
                {lic.doc_issued ? 'issued' : 'not issued'}
              </Badge>
              {lic.doc_hash && (
                <Text ff="monospace" size="xs" c="dimmed">
                  sha256:{lic.doc_hash.slice(0, 16)}…
                </Text>
              )}
            </Group>
          </Group>
        </Stack>
      </Card>

      <Title order={2}>Activated appliances</Title>
      {instances.length === 0 && <Text c="dimmed">No appliances activated on this licence.</Text>}
      {instances.length > 0 && (
        <Card withBorder padding="0">
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Last seen</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {instances.map((inst) => (
                <Table.Tr key={inst.id}>
                  <Table.Td>
                    <Link to="/instances/$instanceId" params={{ instanceId: inst.id }}>
                      {inst.name || inst.instance_id}
                    </Link>
                  </Table.Td>
                  <Table.Td>{inst.appliance_version || '—'}</Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      <Badge variant="light">{inst.status}</Badge>
                      {inst.suspected_clone && <Badge color="red">suspected clone</Badge>}
                    </Group>
                  </Table.Td>
                  <Table.Td>{formatTime(inst.last_seen_at)}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/licences/$licenceId')({
  component: () => (
    <RequireAuth>
      <LicenceDetailPage />
    </RequireAuth>
  ),
});
