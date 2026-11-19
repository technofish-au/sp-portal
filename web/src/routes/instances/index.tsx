import { Alert, Badge, Button, Card, Group, Loader, Stack, Table, Text, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { api, apiPost, type Instance, type Release } from '../../api';
import { RequireAuth } from '../../auth';
import { useCurrentOrg, useMe } from '../../me';
import { formatTime } from '../../ui';
import { compareVersions } from '../../version';

function InstancesPage() {
  const org = useCurrentOrg();
  const me = useMe();
  const queryClient = useQueryClient();
  const role = me.data?.organisations.find((o) => o.org.id === org?.org.id)?.role ?? 'viewer';
  const canWrite = role !== 'viewer';

  const instances = useQuery({
    queryKey: ['instances', org?.org.id],
    enabled: !!org,
    queryFn: () => api<{ instances: Instance[] }>(`/v1/instances?org_id=${org!.org.id}`),
  });
  const releases = useQuery({
    queryKey: ['releases'],
    queryFn: () => api<{ releases: Release[] }>('/v1/releases'),
  });
  // The newest published stable platform release sets the update badges.
  const latest = releases.data?.releases.find(
    (r) => r.component === 'platform' && r.channel === 'stable',
  );

  const deactivate = useMutation({
    mutationFn: (instanceId: string) =>
      apiPost(`/v1/instances/${instanceId}/deactivate`, {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['instances', org?.org.id] }),
  });

  return (
    <Stack gap="md">
      <Title order={1}>Instances</Title>
      {instances.isLoading && <Loader />}
      {instances.isError && <Alert color="red">Failed to load instances.</Alert>}
      {deactivate.isError && (
        <Alert color="red">Deactivate failed: {deactivate.error.message}</Alert>
      )}
      {instances.data && instances.data.instances.length === 0 && (
        <Text c="dimmed">No appliances registered yet — activate one from its console.</Text>
      )}
      {instances.data && instances.data.instances.length > 0 && (
        <Card withBorder padding="0">
          <Table striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Licence</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Last seen</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {instances.data.instances.map((inst) => {
                const behind = latest && compareVersions(inst.appliance_version, latest.version) < 0;
                return (
                  <Table.Tr key={inst.id}>
                    <Table.Td>
                      <Link to="/instances/$instanceId" params={{ instanceId: inst.id }}>
                        {inst.name || inst.instance_id}
                      </Link>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        {inst.appliance_version || '—'}
                        {behind && latest?.security && (
                          <Badge color="red" variant="filled">
                            security update
                          </Badge>
                        )}
                        {behind && !latest?.security && (
                          <Badge color="yellow" variant="light">
                            update available
                          </Badge>
                        )}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text ff="monospace" size="xs">
                        {inst.licence_key || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        <Badge
                          variant="light"
                          color={inst.status === 'active' ? 'green' : 'gray'}
                        >
                          {inst.status}
                        </Badge>
                        {inst.suspected_clone && <Badge color="red">suspected clone</Badge>}
                      </Group>
                    </Table.Td>
                    <Table.Td>{formatTime(inst.last_seen_at)}</Table.Td>
                    <Table.Td>
                      {canWrite && inst.status !== 'decommissioned' && (
                        <Button
                          size="compact-sm"
                          variant="light"
                          color="red"
                          loading={deactivate.isPending && deactivate.variables === inst.id}
                          onClick={() => {
                            if (window.confirm(`Deactivate "${inst.name || inst.instance_id}"? This frees the licence seat.`)) {
                              deactivate.mutate(inst.id);
                            }
                          }}
                        >
                          Deactivate
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Card>
      )}
      {latest && (
        <Text size="sm" c="dimmed">
          Latest release: {latest.component} {latest.version}
          {latest.security ? ' (security)' : ''}
        </Text>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/instances/')({
  component: () => (
    <RequireAuth>
      <InstancesPage />
    </RequireAuth>
  ),
});
