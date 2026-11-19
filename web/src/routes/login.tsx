import { Alert, Button, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { ApiError, apiPost } from '../api';

type Step =
  | { kind: 'credentials' }
  | { kind: 'totp' }
  | { kind: 'setup'; uri: string; secret: string };

interface LoginResponse {
  status: 'ok' | 'totp_required' | 'totp_setup_required';
}

function LoginPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>({ kind: 'credentials' });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
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

  const submitLogin = () =>
    run(async () => {
      const res = await apiPost<LoginResponse>('/v1/auth/login', { email, password });
      if (res.status === 'ok') {
        await navigate({ to: '/' });
      } else if (res.status === 'totp_required') {
        setStep({ kind: 'totp' });
      } else {
        const s = await apiPost<{ provisioning_uri: string; secret: string }>(
          '/v1/auth/totp/setup',
          {},
        );
        setStep({ kind: 'setup', uri: s.provisioning_uri, secret: s.secret });
      }
    });

  const submitTOTP = () =>
    run(async () => {
      await apiPost('/v1/auth/login/totp', { code });
      await navigate({ to: '/' });
    });

  const submitEnable = () =>
    run(async () => {
      await apiPost('/v1/auth/totp/enable', { code });
      await navigate({ to: '/' });
    });

  return (
    <Stack gap="md" maw={420} mx="auto" mt="xl">
      <Title order={1}>Sign in</Title>
      {error && <Alert color="red">{error}</Alert>}

      {step.kind === 'credentials' && (
        <>
          <TextInput
            label="Email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.currentTarget.value)}
          />
          <PasswordInput
            label="Password"
            required
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <Button onClick={submitLogin} loading={busy}>
            Sign in
          </Button>
          <Text size="sm">
            No account? <Link to="/signup">Create one</Link>
          </Text>
        </>
      )}

      {step.kind === 'totp' && (
        <>
          <Text size="sm" c="dimmed">
            Enter the 6-digit code from your authenticator app.
          </Text>
          <TextInput
            label="TOTP code"
            required
            value={code}
            onChange={(e) => setCode(e.currentTarget.value)}
          />
          <Button onClick={submitTOTP} loading={busy}>
            Verify
          </Button>
        </>
      )}

      {step.kind === 'setup' && (
        <>
          <Alert color="yellow">
            Organisation owners must enable two-factor authentication.
          </Alert>
          <Text size="sm">
            Add this to your authenticator app, then enter the code it shows:
          </Text>
          <Text size="xs" ff="monospace" style={{ wordBreak: 'break-all' }}>
            {step.uri}
          </Text>
          <Text size="sm">
            Secret: <code>{step.secret}</code>
          </Text>
          <TextInput
            label="TOTP code"
            required
            value={code}
            onChange={(e) => setCode(e.currentTarget.value)}
          />
          <Button onClick={submitEnable} loading={busy}>
            Enable and continue
          </Button>
        </>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/login')({
  component: LoginPage,
});
