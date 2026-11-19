import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Loader,
  Modal,
  NumberInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { api, apiPost, type AdminOrgDetail } from '../../api';
import { AdminNav } from '../../adminNav';
import { RequireStaff } from '../../auth';
import { formatTime, STATUS_COLOR } from '../../ui';

function AdminOrgPage() {
  const { orgId } = Route.useParams();
  const queryClient = useQueryClient();
  const [issueOpen, setIssueOpen] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [form, setForm] = useState({ kind: 'subscription', plan: 'pro', max_instances: 2, expires_at: '' });

  const detail = useQuery({
    queryKey: ['admin-org', orgId],
    queryFn: () => api<AdminOrgDetail>(`/v1/admin/organisations/${orgId}`),
  });
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ['admin-org', orgId] });

  const revoke = useMutation({
    mutationFn: (licenceId: string) => apiPost(`/v1/admin/licences/${licenceId}/revoke`, {}),
    onSuccess: refresh,
  });
  const reissue = useMutation({
    mutationFn: (licenceId: string) =>
      apiPost<{ licence: { licence_key: string } }>(`/v1/admin/licences/${licenceId}/reissue`, {}),
    onSuccess: (res) => {
      setNewKey(res.licence.licence_key);
      refresh();
    },
  });
  const issue = useMutation({
    mutationFn: () =>
      apiPost<{ licence_key: string }>('/v1/admin/licences', {
        org_id: orgId,
        kind: form.kind,
        plan: form.plan,
        max_instances: form.max_instances,
        expires_at: form.expires_at,
      }),
    onSuccess: (res) => {
      setIssueOpen(false);
      setNewKey(res.licence_key);
      refresh();
    },
  });
  const opError = revoke.error ?? reissue.error ?? issue.error;

  if (detail.isLoading) return <Loader mt="xl" />;
  if (detail.isError || !detail.data) {
    return <Alert color="red">Failed to load the organisation.</Alert>;
  }
  const { org, members, licences, instances, subscription } = detail.data;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{org.name}</Title>
        <AdminNav />
      </Group>
      {newKey && (
        <Alert color="green" withCloseButton onClose={() => setNewKey(null)}>
          New licence key: <code>{newKey}</code>
        </Alert>
      )}
      {opError && <Alert color="red">{opError.message}</Alert>}

      <Card withBorder maw={720}>
        <Stack gap="xs">
          <Group justify="space-between">
            <Text c="dimmed">Slug</Text>
            <Text ff="monospace">{org.slug}</Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Billing email</Text>
            <Text>{org.billing_email || '—'}</Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Tax id</Text>
            <Text>{org.tax_id || '—'}</Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Stripe customer</Text>
            <Text ff="monospace" size="sm">
              {org.stripe_customer_id ?? '—'}
            </Text>
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Subscription</Text>
            {subscription ? (
              <Group gap="xs">
                <Text>{subscription.plan}</Text>
                <Badge color={STATUS_COLOR[subscription.status] ?? 'gray'}>
                  {subscription.status}
                </Badge>
              </Group>
            ) : (
              <Text>—</Text>
            )}
          </Group>
          <Group justify="space-between">
            <Text c="dimmed">Created</Text>
            <Text>{formatTime(org.created_at)}</Text>
          </Group>
        </Stack>
      </Card>

      <Group justify="space-between">
        <Title order={2}>Licences</Title>
        <Button size="sm" variant="light" onClick={() => setIssueOpen(true)}>
          Issue licence
        </Button>
      </Group>
      <Card withBorder padding="0">
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Key</Table.Th>
              <Table.Th>Kind</Table.Th>
              <Table.Th>Plan</Table.Th>
              <Table.Th>Seats</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Expires</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {licences.map((lic) => (
              <Table.Tr key={lic.id}>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {lic.licence_key}
                  </Text>
                </Table.Td>
                <Table.Td>{lic.kind}</Table.Td>
                <Table.Td>{lic.plan}</Table.Td>
                <Table.Td>
                  {lic.seats_used}/{lic.max_instances}
                </Table.Td>
                <Table.Td>
                  <Badge color={STATUS_COLOR[lic.status] ?? 'gray'}>{lic.status}</Badge>
                </Table.Td>
                <Table.Td>{formatTime(lic.expires_at)}</Table.Td>
                <Table.Td>
                  <Group gap="xs">
                    {lic.status !== 'revoked' && (
                      <Button
                        size="compact-sm"
                        variant="light"
                        color="red"
                        onClick={() => {
                          if (window.confirm(`Revoke ${lic.licence_key}?`)) {
                            revoke.mutate(lic.id);
                          }
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                    <Button
                      size="compact-sm"
                      variant="light"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Reissue ${lic.licence_key}? A replacement key is minted and this one is revoked.`,
                          )
                        ) {
                          reissue.mutate(lic.id);
                        }
                      }}
                    >
                      Reissue
                    </Button>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {licences.length === 0 && (
              <Table.Tr>
                <Table.Td c="dimmed">No licences</Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Card>

      <Title order={2}>Members</Title>
      <Card withBorder padding="0">
        <Table striped>
          <Table.Tbody>
            {members.map((m) => (
              <Table.Tr key={m.id}>
                <Table.Td>{m.email}</Table.Td>
                <Table.Td>{m.display_name || '—'}</Table.Td>
                <Table.Td>
                  <Badge variant="light">{m.role}</Badge>
                </Table.Td>
              </Table.Tr>
            ))}
            {members.length === 0 && (
              <Table.Tr>
                <Table.Td c="dimmed">No members</Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Card>

      <Title order={2}>Instances</Title>
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
            {instances.map((i) => (
              <Table.Tr key={i.id}>
                <Table.Td>{i.name || i.instance_id}</Table.Td>
                <Table.Td>{i.appliance_version || '—'}</Table.Td>
                <Table.Td>
                  <Group gap="xs">
                    <Badge variant="light">{i.status}</Badge>
                    {i.suspected_clone && <Badge color="red">suspected clone</Badge>}
                  </Group>
                </Table.Td>
                <Table.Td>{formatTime(i.last_seen_at)}</Table.Td>
              </Table.Tr>
            ))}
            {instances.length === 0 && (
              <Table.Tr>
                <Table.Td c="dimmed">No instances</Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Card>

      <Modal opened={issueOpen} onClose={() => setIssueOpen(false)} title="Issue licence">
        <Stack gap="sm">
          <Select
            label="Kind"
            data={['trial', 'subscription', 'perpetual']}
            value={form.kind}
            onChange={(v) => setForm((f) => ({ ...f, kind: v ?? 'subscription' }))}
          />
          <Select
            label="Plan"
            data={['trial', 'starter', 'pro', 'enterprise']}
            value={form.plan}
            onChange={(v) => setForm((f) => ({ ...f, plan: v ?? 'pro' }))}
          />
          <NumberInput
            label="Max instances"
            min={1}
            value={form.max_instances}
            onChange={(v) => setForm((f) => ({ ...f, max_instances: Number(v) || 1 }))}
          />
          <TextInput
            label="Expires at (RFC3339, empty = never)"
            placeholder="2027-01-01T00:00:00Z"
            value={form.expires_at}
            onChange={(e) => setForm((f) => ({ ...f, expires_at: e.currentTarget.value }))}
          />
          <Button loading={issue.isPending} onClick={() => issue.mutate()}>
            Issue
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}

export const Route = createFileRoute('/admin/organisations/$orgId')({
  component: () => (
    <RequireStaff>
      <AdminOrgPage />
    </RequireStaff>
  ),
});
