import { Alert, Stack, Text, Title } from '@mantine/core';
import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { api } from '../api';

function VerifyEmailPage() {
  const { token } = Route.useSearch();
  const [state, setState] = useState<'pending' | 'ok' | 'error'>(() =>
    token ? 'pending' : 'error',
  );

  useEffect(() => {
    if (!token) {
      return;
    }
    let cancelled = false;
    api<{ status: string }>(`/v1/auth/verify-email?token=${encodeURIComponent(token)}`)
      .then(() => {
        if (!cancelled) setState('ok');
      })
      .catch(() => {
        if (!cancelled) setState('error');
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <Stack gap="md" maw={480} mx="auto" mt="xl">
      <Title order={1}>Email verification</Title>
      {state === 'pending' && <Text>Verifying…</Text>}
      {state === 'ok' && (
        <Alert color="green">
          Email verified. <Link to="/">Continue to the dashboard</Link>
        </Alert>
      )}
      {state === 'error' && (
        <Alert color="red">The verification link is invalid or has expired.</Alert>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/verify-email')({
  validateSearch: (search: Record<string, unknown>) => ({
    token: typeof search.token === 'string' ? search.token : '',
  }),
  component: VerifyEmailPage,
});
