import { Alert, Badge, Card, Code, Group, Loader, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { api, type Instance, type InstanceReport, type Licence } from '../../api';
import { RequireAuth } from '../../auth';
import { formatTime } from '../../ui';

interface InstanceDetail {
  instance: Instance;
  licence: Licence | null;
}

function InstanceDetailPage() {
  const { instanceId } = Route.useParams();
  const detail = useQuery({
    queryKey: ['instance', instanceId],
    queryFn: () => api<InstanceDetail>(`/v1/instances/${instanceId}`),
  });
  const reports = useQuery({
    queryKey: ['instance-reports', instanceId],
    queryFn: () => api<{ reports: InstanceReport[] }>(`/v1/instances/${instanceId}/reports`),
  });

  if (detail.isLoading) return <Loader mt="xl" />;
  if (detail.isError || !detail.data) {
    return <Alert color="red">Failed to load the instance.</Alert>;
  }
  const { instance: inst, licence } = detail.data;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{inst.name || inst.instance_id}</Title>
        <Group gap="xs">
          <Badge size="lg" color={inst.status === 'active' ? 'green' : 'gray'}>
            {inst.status}
          </Badge>
          {inst.suspected_clone && (
            <Badge size="lg" color="red">
              suspected clone
            </Badge>
          )}
        </Group>
      </Group>

      {inst.suspected_clone && (
        <Alert color="red">
          A different signing key presented this instance identity — verify the appliance has
          not been cloned before trusting its check-ins.
        </Alert>
      )}

      <Card withBorder maw={720}>
        <Stack gap="xs">
          <Group justify="space-between">
            <Text c="dimmed">Instance id</Text>
            <Text ff="monospace" size="sm">
              {inst.instance_id}
            </Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Appliance version</Text>
            <Text>{inst.appliance_version || '—'}</Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Licence</Text>
            {licence ? (
              <Link to="/licences/$licenceId" params={{ licenceId: licence.id }}>
                <Text ff="monospace" size="sm">
                  {licence.licence_key}
                </Text>
              </Link>
            ) : (
              <Text>—</Text>
            )}
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Registered</Text>
            <Text>{formatTime(inst.created_at)}</Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Last check-in</Text>
            <Text>{formatTime(inst.last_seen_at)}</Text>
          </Group>
        </Stack>
      </Card>

      <Title order={2}>Check-in history</Title>
      {reports.isLoading && <Loader />}
      {reports.data && reports.data.reports.length === 0 && (
        <Text c="dimmed">No check-ins recorded yet.</Text>
      )}
      {reports.data && reports.data.reports.length > 0 && (
        <Card withBorder padding="0">
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Reported at</Table.Th>
                <Table.Th>Payload</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {reports.data.reports.map((rep) => (
                <Table.Tr key={rep.id}>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}>
                    {formatTime(rep.reported_at)}
                  </Table.Td>
                  <Table.Td>
                    <Code block>{JSON.stringify(rep.payload, null, 2)}</Code>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/instances/$instanceId')({
  component: () => (
    <RequireAuth>
      <InstanceDetailPage />
    </RequireAuth>
  ),
});
