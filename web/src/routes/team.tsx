import {
  Alert,
  Badge,
  Button,
  Card,
  Loader,
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
import { api, apiDelete, apiPatch, apiPost, type Member } from '../api';
import { RequireAuth } from '../auth';
import { useCurrentOrg, useMe } from '../me';

const ROLES = ['owner', 'admin', 'member', 'viewer'];

function TeamPage() {
  const org = useCurrentOrg();
  const me = useMe();
  const queryClient = useQueryClient();
  const role = org?.role ?? 'viewer';
  const canManage = role === 'owner' || role === 'admin';

  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [inviteRole, setInviteRole] = useState<string | null>('member');
  const [message, setMessage] = useState<string | null>(null);

  const members = useQuery({
    queryKey: ['members', org?.org.id],
    enabled: !!org,
    queryFn: () => api<{ members: Member[] }>(`/v1/organisations/${org!.org.id}/members`),
  });

  const invite = useMutation({
    mutationFn: () =>
      apiPost(`/v1/organisations/${org!.org.id}/invites`, {
        email,
        display_name: name,
        role: inviteRole ?? 'member',
      }),
    onSuccess: () => {
      setMessage(`Invite sent to ${email}.`);
      setEmail('');
      setName('');
      void queryClient.invalidateQueries({ queryKey: ['members', org?.org.id] });
    },
  });
  const setRole = useMutation({
    mutationFn: (v: { userId: string; role: string }) =>
      apiPatch(`/v1/organisations/${org!.org.id}/members/${v.userId}`, { role: v.role }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['members', org?.org.id] }),
  });
  const remove = useMutation({
    mutationFn: (userId: string) =>
      apiDelete(`/v1/organisations/${org!.org.id}/members/${userId}`),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['members', org?.org.id] }),
  });
  const actionError = invite.error ?? setRole.error ?? remove.error;

  return (
    <Stack gap="md">
      <Title order={1}>Team</Title>
      <Text c="dimmed">Members of {org?.org.name}.</Text>
      {message && (
        <Alert color="green" onClose={() => setMessage(null)} withCloseButton>
          {message}
        </Alert>
      )}
      {actionError && <Alert color="red">{actionError.message}</Alert>}
      {members.isLoading && <Loader />}
      {members.data && (
        <Card withBorder padding="0">
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Email</Table.Th>
                <Table.Th>Name</Table.Th>
                <Table.Th>Role</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {members.data.members.map((m) => (
                <Table.Tr key={m.id}>
                  <Table.Td>
                    {m.email}
                    {m.id === me.data?.user.id && (
                      <Badge ml="xs" variant="light">
                        you
                      </Badge>
                    )}
                  </Table.Td>
                  <Table.Td>{m.display_name || '—'}</Table.Td>
                  <Table.Td>
                    {canManage ? (
                      <Select
                        size="xs"
                        data={ROLES}
                        value={m.role}
                        onChange={(v) => v && setRole.mutate({ userId: m.id, role: v })}
                        w={120}
                      />
                    ) : (
                      <Badge variant="light">{m.role}</Badge>
                    )}
                  </Table.Td>
                  <Table.Td>
                    {canManage && (
                      <Button
                        size="compact-sm"
                        variant="light"
                        color="red"
                        onClick={() => {
                          if (window.confirm(`Remove ${m.email} from the organisation?`)) {
                            remove.mutate(m.id);
                          }
                        }}
                      >
                        Remove
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}

      {canManage && (
        <Card withBorder maw={560}>
          <Title order={3} mb="sm">
            Invite a member
          </Title>
          <Stack gap="sm">
            <TextInput
              label="Email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.currentTarget.value)}
            />
            <TextInput
              label="Display name"
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
            />
            <Select
              label="Role"
              data={ROLES}
              value={inviteRole}
              onChange={setInviteRole}
            />
            <Button
              disabled={!email}
              loading={invite.isPending}
              onClick={() => invite.mutate()}
            >
              Send invite
            </Button>
          </Stack>
        </Card>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/team')({
  component: () => (
    <RequireAuth>
      <TeamPage />
    </RequireAuth>
  ),
});
