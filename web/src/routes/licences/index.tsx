import { Alert, Badge, Card, Group, Loader, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { api, type Licence } from '../../api';
import { RequireAuth } from '../../auth';
import { useCurrentOrg } from '../../me';
import { formatTime, STATUS_COLOR } from '../../ui';

function LicencesPage() {
  const org = useCurrentOrg();
  const q = useQuery({
    queryKey: ['licences', org?.org.id],
    enabled: !!org,
    queryFn: () => api<{ licences: Licence[] }>(`/v1/licences?org_id=${org!.org.id}`),
  });

  return (
    <Stack gap="md">
      <Title order={1}>Licences</Title>
      {q.isLoading && <Loader />}
      {q.isError && <Alert color="red">Failed to load licences.</Alert>}
      {q.data && q.data.licences.length === 0 && (
        <Text c="dimmed">No licences issued for {org?.org.name} yet.</Text>
      )}
      {q.data && q.data.licences.length > 0 && (
        <Card withBorder padding="0">
          <Table striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Licence key</Table.Th>
                <Table.Th>Kind</Table.Th>
                <Table.Th>Plan</Table.Th>
                <Table.Th>Seats</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Document</Table.Th>
                <Table.Th>Expires</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {q.data.licences.map((lic) => (
                <Table.Tr key={lic.id}>
                  <Table.Td>
                    <Link to="/licences/$licenceId" params={{ licenceId: lic.id }}>
                      <Text ff="monospace" size="sm">
                        {lic.licence_key}
                      </Text>
                    </Link>
                  </Table.Td>
                  <Table.Td>{lic.kind}</Table.Td>
                  <Table.Td>{lic.plan}</Table.Td>
                  <Table.Td>
                    {lic.seats_used}/{lic.max_instances}
                  </Table.Td>
                  <Table.Td>
                    <Badge color={STATUS_COLOR[lic.status] ?? 'gray'}>{lic.status}</Badge>
                  </Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={lic.doc_issued ? 'blue' : 'gray'}>
                      {lic.doc_issued ? 'issued' : 'not issued'}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{formatTime(lic.expires_at)}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}
      <Group>
        <Text size="sm" c="dimmed">
          Air-gapped appliances use offline activation bundles — see the licence detail for
          document status.
        </Text>
      </Group>
    </Stack>
  );
}

export const Route = createFileRoute('/licences/')({
  component: () => (
    <RequireAuth>
      <LicencesPage />
    </RequireAuth>
  ),
});
