import { Alert, Button, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { ApiError, apiPost } from '../api';

interface SignupResponse {
  status: string;
}

function SignupPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [totp, setTotp] = useState<{ uri: string; secret: string } | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'request failed');
    } finally {
      setBusy(false);
    }
  }

  const submit = () =>
    run(async () => {
      await apiPost<SignupResponse>('/v1/auth/signup', {
        email,
        password,
        display_name: displayName,
        org_name: orgName,
      });
      // New owners land on the pending-setup stage: enrol TOTP now.
      const s = await apiPost<{ provisioning_uri: string; secret: string }>(
        '/v1/auth/totp/setup',
        {},
      );
      setTotp({ uri: s.provisioning_uri, secret: s.secret });
    });

  const enable = () =>
    run(async () => {
      await apiPost('/v1/auth/totp/enable', { code });
      await navigate({ to: '/' });
    });

  return (
    <Stack gap="md" maw={420} mx="auto" mt="xl">
      <Title order={1}>Create your account</Title>
      <Text size="sm" c="dimmed">
        Sign-up starts a 30-day / 25-machine trial.
      </Text>
      {error && <Alert color="red">{error}</Alert>}

      {!totp && (
        <>
          <TextInput
            label="Organisation name"
            required
            value={orgName}
            onChange={(e) => setOrgName(e.currentTarget.value)}
          />
          <TextInput
            label="Your name"
            value={displayName}
            onChange={(e) => setDisplayName(e.currentTarget.value)}
          />
          <TextInput
            label="Email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.currentTarget.value)}
          />
          <PasswordInput
            label="Password"
            description="At least 8 characters"
            required
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <Button onClick={submit} loading={busy}>
            Create account
          </Button>
          <Text size="sm">
            Already registered? <Link to="/login">Sign in</Link>
          </Text>
        </>
      )}

      {totp && (
        <>
          <Alert color="yellow">
            Account created. As an organisation owner you must enable two-factor
            authentication before continuing.
          </Alert>
          <Text size="xs" ff="monospace" style={{ wordBreak: 'break-all' }}>
            {totp.uri}
          </Text>
          <Text size="sm">
            Secret: <code>{totp.secret}</code>
          </Text>
          <TextInput
            label="TOTP code"
            required
            value={code}
            onChange={(e) => setCode(e.currentTarget.value)}
          />
          <Button onClick={enable} loading={busy}>
            Enable and continue
          </Button>
        </>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/signup')({
  component: SignupPage,
});
