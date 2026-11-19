import {
  Alert,
  Badge,
  Card,
  Grid,
  Group,
  Loader,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { api, type Estate, type SearchResults } from '../../api';
import { AdminNav } from '../../adminNav';
import { RequireStaff } from '../../auth';
import { formatTime } from '../../ui';

function AdminHome() {
  const navigate = useNavigate();
  const [term, setTerm] = useState('');
  const [submitted, setSubmitted] = useState('');

  const search = useQuery({
    queryKey: ['admin-search', submitted],
    enabled: submitted.length > 0,
    queryFn: () => api<SearchResults>(`/v1/admin/search?q=${encodeURIComponent(submitted)}`),
  });
  const estate = useQuery({
    queryKey: ['admin-estate'],
    queryFn: () => api<Estate>('/v1/admin/estate'),
  });

  const t = estate.data?.totals;
  const totals: [string, number | undefined][] = [
    ['Organisations', t?.organisations],
    ['Users', t?.users],
    ['Live licences', t?.live_licences],
    ['Active instances', t?.active_instances],
    ['Suspected clones', t?.suspected_clones],
    ['Seen < 24h', t?.seen_24h],
    ['Seen < 7d', t?.seen_7d],
    ['Stale > 7d', t?.stale_7d],
  ];

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>Staff admin</Title>
        <AdminNav />
      </Group>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setSubmitted(term.trim());
        }}
      >
        <TextInput
          label="Search"
          placeholder="Org name, user email, licence key, instance name or id…"
          value={term}
          onChange={(e) => setTerm(e.currentTarget.value)}
        />
      </form>

      {search.isLoading && <Loader />}
      {search.isError && <Alert color="red">Search failed.</Alert>}
      {search.data && (
        <Stack gap="sm">
          {search.data.organisations.length > 0 && (
            <Card withBorder padding="sm">
              <Title order={4} mb="xs">
                Organisations
              </Title>
              {search.data.organisations.map((o) => (
                <Group key={o.id} justify="space-between">
                  <Link to="/admin/organisations/$orgId" params={{ orgId: o.id }}>
                    {o.name}
                  </Link>
                  <Text size="sm" c="dimmed">
                    {o.slug} · {o.billing_email}
                  </Text>
                </Group>
              ))}
            </Card>
          )}
          {search.data.users.length > 0 && (
            <Card withBorder padding="sm">
              <Title order={4} mb="xs">
                Users
              </Title>
              {search.data.users.map((u) => (
                <Group key={u.id} justify="space-between">
                  <Text>
                    {u.email} {u.display_name && `(${u.display_name})`}
                  </Text>
                  <Group gap="xs">
                    {u.is_platform_admin && <Badge color="grape">staff</Badge>}
                    {u.totp_enabled && <Badge variant="light">totp</Badge>}
                    {u.disabled_at && <Badge color="red">disabled</Badge>}
                    {!u.email_verified && <Badge color="yellow">unverified</Badge>}
                  </Group>
                </Group>
              ))}
            </Card>
          )}
          {search.data.licences.length > 0 && (
            <Card withBorder padding="sm">
              <Title order={4} mb="xs">
                Licences
              </Title>
              {search.data.licences.map((l) => (
                <Group key={l.id} justify="space-between">
                  <Text
                    ff="monospace"
                    size="sm"
                    style={{ cursor: 'pointer' }}
                    onClick={() =>
                      void navigate({
                        to: '/admin/organisations/$orgId',
                        params: { orgId: l.org_id },
                      })
                    }
                  >
                    {l.licence_key}
                  </Text>
                  <Group gap="xs">
                    <Badge variant="light">{l.plan}</Badge>
                    <Badge color={l.status === 'active' ? 'green' : 'red'}>{l.status}</Badge>
                  </Group>
                </Group>
              ))}
            </Card>
          )}
          {search.data.instances.length > 0 && (
            <Card withBorder padding="sm">
              <Title order={4} mb="xs">
                Instances
              </Title>
              {search.data.instances.map((i) => (
                <Group key={i.id} justify="space-between">
                  <Text
                    style={{ cursor: 'pointer' }}
                    onClick={() =>
                      void navigate({
                        to: '/admin/organisations/$orgId',
                        params: { orgId: i.org_id },
                      })
                    }
                  >
                    {i.name || i.instance_id}
                  </Text>
                  <Group gap="xs">
                    <Text size="sm" c="dimmed">
                      {i.appliance_version || '—'}
                    </Text>
                    {i.suspected_clone && <Badge color="red">suspected clone</Badge>}
                  </Group>
                </Group>
              ))}
            </Card>
          )}
          {search.data.organisations.length === 0 &&
            search.data.users.length === 0 &&
            search.data.licences.length === 0 &&
            search.data.instances.length === 0 && (
              <Text c="dimmed">No matches for “{submitted}”.</Text>
            )}
        </Stack>
      )}

      <Title order={2}>Estate</Title>
      {estate.isLoading && <Loader />}
      {estate.data && (
        <Grid>
          <Grid.Col span={{ base: 12, md: 7 }}>
            <SimpleGrid cols={4}>
              {totals.map(([label, value]) => (
                <Card key={label} withBorder padding="sm">
                  <Text size="xs" c="dimmed">
                    {label}
                  </Text>
                  <Text fw={700} size="xl">
                    {value ?? '—'}
                  </Text>
                </Card>
              ))}
            </SimpleGrid>
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 5 }}>
            <Card withBorder padding="sm">
              <Title order={4} mb="xs">
                Instances per version
              </Title>
              <Table>
                <Table.Tbody>
                  {estate.data.versions.map((v) => (
                    <Table.Tr key={v.appliance_version || '(unknown)'}>
                      <Table.Td>{v.appliance_version || '(unknown)'}</Table.Td>
                      <Table.Td ta="right">{v.instances}</Table.Td>
                    </Table.Tr>
                  ))}
                  {estate.data.versions.length === 0 && (
                    <Table.Tr>
                      <Table.Td c="dimmed">No live instances</Table.Td>
                    </Table.Tr>
                  )}
                </Table.Tbody>
              </Table>
              <Text size="xs" c="dimmed" mt="xs">
                Suspected clones: {estate.data.totals.suspected_clones} · updated{' '}
                {formatTime(new Date().toISOString())}
              </Text>
            </Card>
          </Grid.Col>
        </Grid>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/admin/')({
  component: () => (
    <RequireStaff>
      <AdminHome />
    </RequireStaff>
  ),
});
