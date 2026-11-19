import { Alert, Button, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { ApiError, apiPost } from '../api';

function AcceptInvitePage() {
  const { token } = Route.useSearch();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await apiPost<{ existing: boolean }>('/v1/auth/accept-invite', {
        token,
        password,
        display_name: name,
      });
      await navigate({ to: res.existing ? '/' : '/' });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'accept failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack gap="md" maw={420} mx="auto" mt="xl">
      <Title order={1}>Accept invite</Title>
      {error && <Alert color="red">{error}</Alert>}
      {!token ? (
        <Alert color="red">
          This invite link is missing its token — use the link from your invite email.
        </Alert>
      ) : (
        <>
          <Text size="sm" c="dimmed">
            Set a password to finish joining the organisation. Already have an account? The
            invite is confirmed automatically.
          </Text>
          <TextInput
            label="Your name"
            value={name}
            onChange={(e) => setName(e.currentTarget.value)}
          />
          <PasswordInput
            label="Password"
            description="At least 8 characters — only needed for a new account"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <Button onClick={submit} loading={busy}>
            Accept invite
          </Button>
        </>
      )}
      <Text size="sm">
        Back to <Link to="/login">sign in</Link>
      </Text>
    </Stack>
  );
}

export const Route = createFileRoute('/accept-invite')({
  validateSearch: (search: Record<string, unknown>) => ({
    token: typeof search.token === 'string' ? search.token : '',
  }),
  component: AcceptInvitePage,
});
