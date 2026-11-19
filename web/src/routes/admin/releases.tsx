import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  Loader,
  Modal,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { api, apiPatch, apiPost, type Release } from '../../api';
import { AdminNav } from '../../adminNav';
import { RequireStaff } from '../../auth';
import { formatBytes, formatTime } from '../../ui';

interface Bundle {
  bundle: string;
  size_bytes: number;
  created_at: string;
}

function AdminReleasesPage() {
  const queryClient = useQueryClient();
  const [registerOpen, setRegisterOpen] = useState(false);
  const [editRelease, setEditRelease] = useState<Release | null>(null);
  const [form, setForm] = useState({
    version: '',
    component: 'platform',
    channel: 'stable',
    artifact_path: '',
    notes: '',
    min_upgrade_from: '',
    security: false,
  });
  const [pruneResult, setPruneResult] = useState<string | null>(null);

  const releases = useQuery({
    queryKey: ['admin-releases'],
    queryFn: () => api<{ releases: Release[] }>('/v1/admin/releases'),
  });
  const bundles = useQuery({
    queryKey: ['admin-bundles'],
    queryFn: () => api<{ bundles: Bundle[] }>('/v1/admin/offline-bundles'),
  });
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['admin-releases'] });
    void queryClient.invalidateQueries({ queryKey: ['admin-bundles'] });
  };

  const action = useMutation({
    mutationFn: ({ id, op }: { id: string; op: 'publish' | 'withdraw' | 'offline-bundle' }) =>
      apiPost(`/v1/admin/releases/${id}/${op}`, {}),
    onSuccess: refresh,
  });
  const patch = useMutation({
    mutationFn: (p: { id: string; security?: boolean; min_upgrade_from?: string }) =>
      apiPatch(`/v1/admin/releases/${p.id}`, {
        security: p.security,
        min_upgrade_from: p.min_upgrade_from,
      }),
    onSuccess: () => {
      setEditRelease(null);
      refresh();
    },
  });
  const register = useMutation({
    mutationFn: () => apiPost<Release>('/v1/admin/releases', form),
    onSuccess: () => {
      setRegisterOpen(false);
      refresh();
    },
  });
  const prune = useMutation({
    mutationFn: (dryRun: boolean) =>
      apiPost<{ removed: string[]; bytes: number }>('/v1/admin/storage/prune', {
        dry_run: dryRun,
        include_withdrawn: true,
      }),
    onSuccess: (res, dryRun) =>
      setPruneResult(
        `${dryRun ? 'Dry run: would remove' : 'Removed'} ${res.removed.length} file(s) (${formatBytes(res.bytes)}).`,
      ),
  });
  const opError = action.error ?? patch.error ?? register.error ?? prune.error;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>Release catalogue</Title>
        <Group gap="xs">
          <AdminNav />
          <Button size="sm" onClick={() => setRegisterOpen(true)}>
            Register release
          </Button>
        </Group>
      </Group>
      {opError && <Alert color="red">{opError.message}</Alert>}
      {pruneResult && (
        <Alert color="blue" withCloseButton onClose={() => setPruneResult(null)}>
          {pruneResult}
        </Alert>
      )}

      {releases.isLoading && <Loader />}
      {releases.data && (
        <Card withBorder padding="0">
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Component</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Channel</Table.Th>
                <Table.Th>Size</Table.Th>
                <Table.Th>State</Table.Th>
                <Table.Th>Min upgrade from</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {releases.data.releases.map((rel) => (
                <Table.Tr key={rel.id}>
                  <Table.Td>{rel.component}</Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      {rel.version}
                      {rel.security && <Badge color="red">security</Badge>}
                    </Group>
                  </Table.Td>
                  <Table.Td>{rel.channel}</Table.Td>
                  <Table.Td>{formatBytes(rel.size_bytes)}</Table.Td>
                  <Table.Td>
                    {rel.withdrawn_at ? (
                      <Badge color="red">withdrawn</Badge>
                    ) : rel.published ? (
                      <Badge color="green">published</Badge>
                    ) : (
                      <Badge color="gray">unpublished</Badge>
                    )}
                  </Table.Td>
                  <Table.Td>{rel.min_upgrade_from || '—'}</Table.Td>
                  <Table.Td>
                    <Group gap="xs" wrap="nowrap">
                      <Button size="compact-sm" variant="light" onClick={() => setEditRelease(rel)}>
                        Edit
                      </Button>
                      {!rel.published && !rel.withdrawn_at && (
                        <Button
                          size="compact-sm"
                          onClick={() => action.mutate({ id: rel.id, op: 'publish' })}
                        >
                          Publish
                        </Button>
                      )}
                      {rel.published && (
                        <Button
                          size="compact-sm"
                          variant="light"
                          color="red"
                          onClick={() => action.mutate({ id: rel.id, op: 'withdraw' })}
                        >
                          Withdraw
                        </Button>
                      )}
                      <Button
                        size="compact-sm"
                        variant="default"
                        onClick={() => action.mutate({ id: rel.id, op: 'offline-bundle' })}
                      >
                        Build .spb
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
              {releases.data.releases.length === 0 && (
                <Table.Tr>
                  <Table.Td c="dimmed">No releases registered</Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Card>
      )}

      <Group justify="space-between">
        <Title order={2}>Offline bundles</Title>
        <Group gap="xs">
          <Button size="sm" variant="light" onClick={() => prune.mutate(true)}>
            Prune (dry run)
          </Button>
          <Button
            size="sm"
            variant="light"
            color="red"
            onClick={() => {
              if (window.confirm('Delete unreferenced release artifacts, including withdrawn?')) {
                prune.mutate(false);
              }
            }}
          >
            Prune storage
          </Button>
        </Group>
      </Group>
      <Card withBorder padding="0">
        <Table striped>
          <Table.Tbody>
            {bundles.data?.bundles.map((b) => (
              <Table.Tr key={b.bundle}>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {b.bundle}
                  </Text>
                </Table.Td>
                <Table.Td>{formatBytes(b.size_bytes)}</Table.Td>
                <Table.Td>{formatTime(b.created_at)}</Table.Td>
              </Table.Tr>
            ))}
            {bundles.data?.bundles.length === 0 && (
              <Table.Tr>
                <Table.Td c="dimmed">No bundles generated</Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Card>

      <Modal opened={registerOpen} onClose={() => setRegisterOpen(false)} title="Register release">
        <Stack gap="sm">
          <Text size="sm" c="dimmed">
            Registers an artifact already staged under storage/releases/ (the CI rsync leg).
          </Text>
          <TextInput
            label="Version"
            required
            value={form.version}
            onChange={(e) => setForm((f) => ({ ...f, version: e.currentTarget.value }))}
          />
          <TextInput
            label="Component"
            value={form.component}
            onChange={(e) => setForm((f) => ({ ...f, component: e.currentTarget.value }))}
          />
          <TextInput
            label="Channel"
            value={form.channel}
            onChange={(e) => setForm((f) => ({ ...f, channel: e.currentTarget.value }))}
          />
          <TextInput
            label="Artifact path (under releases/)"
            required
            placeholder="platform/1.4.2/sp-platform-1.4.2.tar.gz"
            value={form.artifact_path}
            onChange={(e) => setForm((f) => ({ ...f, artifact_path: e.currentTarget.value }))}
          />
          <TextInput
            label="Min upgrade from"
            value={form.min_upgrade_from}
            onChange={(e) => setForm((f) => ({ ...f, min_upgrade_from: e.currentTarget.value }))}
          />
          <Textarea
            label="Notes"
            value={form.notes}
            onChange={(e) => setForm((f) => ({ ...f, notes: e.currentTarget.value }))}
          />
          <Checkbox
            label="Security release"
            checked={form.security}
            onChange={(e) => setForm((f) => ({ ...f, security: e.currentTarget.checked }))}
          />
          <Button loading={register.isPending} onClick={() => register.mutate()}>
            Register
          </Button>
        </Stack>
      </Modal>

      <Modal opened={!!editRelease} onClose={() => setEditRelease(null)} title="Edit release">
        {editRelease && (
          <Stack gap="sm">
            <Text fw={600}>
              {editRelease.component} {editRelease.version}
            </Text>
            <Checkbox
              label="Security release"
              checked={editRelease.security}
              onChange={(e) =>
                setEditRelease((r) => r && { ...r, security: e.currentTarget.checked })
              }
            />
            <TextInput
              label="Min upgrade from"
              value={editRelease.min_upgrade_from}
              onChange={(e) =>
                setEditRelease((r) => r && { ...r, min_upgrade_from: e.currentTarget.value })
              }
            />
            <Button
              loading={patch.isPending}
              onClick={() =>
                patch.mutate({
                  id: editRelease.id,
                  security: editRelease.security,
                  min_upgrade_from: editRelease.min_upgrade_from,
                })
              }
            >
              Save
            </Button>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}

export const Route = createFileRoute('/admin/releases')({
  component: () => (
    <RequireStaff>
      <AdminReleasesPage />
    </RequireStaff>
  ),
});
