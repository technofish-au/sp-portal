import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  CopyButton,
  Group,
  Loader,
  Stack,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { useMutation, useQuery } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { api, apiPost, type DownloadURL, type Release } from '../api';
import { RequireAuth } from '../auth';
import { useCurrentOrg } from '../me';
import { formatBytes, formatTime } from '../ui';

function DownloadsPage() {
  const org = useCurrentOrg();
  const [minted, setMinted] = useState<Record<string, DownloadURL>>({});
  const releases = useQuery({
    queryKey: ['releases'],
    queryFn: () => api<{ releases: Release[] }>('/v1/releases'),
  });
  const mint = useMutation({
    mutationFn: (releaseId: string) =>
      apiPost<DownloadURL>(`/v1/releases/${releaseId}/download-url`, {
        org_id: org?.org.id,
      }),
    onSuccess: (res, releaseId) => setMinted((m) => ({ ...m, [releaseId]: res })),
  });

  return (
    <Stack gap="md">
      <Title order={1}>Downloads</Title>
      <Text c="dimmed">
        Release artifacts for {org?.org.name}. Download links are signed and expire after 15
        minutes.
      </Text>
      {releases.isLoading && <Loader />}
      {releases.isError && <Alert color="red">Failed to load the release catalogue.</Alert>}
      {mint.isError && <Alert color="red">Download failed: {mint.error.message}</Alert>}
      {releases.data && releases.data.releases.length === 0 && (
        <Text c="dimmed">No releases published yet.</Text>
      )}
      {releases.data && releases.data.releases.length > 0 && (
        <Card withBorder padding="0">
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Component</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Channel</Table.Th>
                <Table.Th>Size</Table.Th>
                <Table.Th>SHA-256</Table.Th>
                <Table.Th>Published</Table.Th>
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
                    <Text ff="monospace" size="xs" c="dimmed">
                      {rel.sha256 ? rel.sha256.slice(0, 16) + '…' : '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>{formatTime(rel.published_at)}</Table.Td>
                  <Table.Td>
                    {minted[rel.id] !== undefined ? (
                      <Group gap="xs">
                        <Anchor href={minted[rel.id]!.url} size="sm">
                          Download
                        </Anchor>
                        <CopyButton value={minted[rel.id]!.url}>
                          {({ copied, copy }) => (
                            <Button size="compact-sm" variant="light" onClick={copy}>
                              {copied ? 'Copied' : 'Copy link'}
                            </Button>
                          )}
                        </CopyButton>
                      </Group>
                    ) : (
                      <Button
                        size="compact-sm"
                        disabled={!org}
                        loading={mint.isPending && mint.variables === rel.id}
                        onClick={() => mint.mutate(rel.id)}
                      >
                        Get download link
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}
      {releases.data?.releases.some((r) => r.notes) && (
        <Stack gap="xs">
          <Title order={3}>Release notes</Title>
          {releases.data.releases
            .filter((r) => r.notes)
            .map((r) => (
              <Card key={r.id} withBorder>
                <Text fw={600}>
                  {r.component} {r.version}
                </Text>
                <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>
                  {r.notes}
                </Text>
              </Card>
            ))}
        </Stack>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/downloads')({
  component: () => (
    <RequireAuth>
      <DownloadsPage />
    </RequireAuth>
  ),
});
