import { Alert, Badge, Button, Card, Group, Loader, Stack, Text, Title } from '@mantine/core';
import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { ApiError, api, apiPost, type MeResponse, type OrgDetail } from '../api';

const STATUS_COLOR: Record<string, string> = {
  trialing: 'blue',
  active: 'green',
  past_due: 'yellow',
  unpaid: 'red',
  cancelled: 'gray',
};

function IndexPage() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [detail, setDetail] = useState<OrgDetail | null>(null);
  const [state, setState] = useState<'loading' | 'anon' | 'ready' | 'error'>('loading');
  const [billingError, setBillingError] = useState<string | null>(null);

  useEffect(() => {
    api<MeResponse>('/v1/auth/me')
      .then(async (m) => {
        setMe(m);
        setState('ready');
        const first = m.organisations[0];
        if (first) {
          const d = await api<OrgDetail>(`/v1/organisations/${first.org.id}`).catch(() => null);
          setDetail(d);
        }
      })
      .catch((e: unknown) => setState(e instanceof ApiError && e.status === 401 ? 'anon' : 'error'));
  }, []);

  async function redirectTo(urlPromise: Promise<{ url: string }>) {
    setBillingError(null);
    try {
      const { url } = await urlPromise;
      window.location.assign(url);
    } catch (e) {
      setBillingError(e instanceof ApiError ? e.message : 'billing unavailable');
    }
  }

  if (state === 'loading') {
    return <Loader mt="xl" />;
  }
  if (state === 'anon') {
    return (
      <Stack gap="md" maw={480} mx="auto" mt="xl">
        <Title order={1}>ServerPerch Portal</Title>
        <Text c="dimmed">Sign in to manage licences, appliances and downloads.</Text>
        <Group>
          <Button component={Link} to="/login">
            Sign in
          </Button>
          <Button component={Link} to="/signup" variant="light">
            Create account
          </Button>
        </Group>
      </Stack>
    );
  }
  if (state === 'error' || !me) {
    return <Alert color="red">Failed to load your account.</Alert>;
  }

  const sub = detail?.subscription;
  const role = detail?.role ?? 'member';
  const canBill = role === 'owner' || role === 'admin';
  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Title order={1}>Dashboard</Title>
        <Text size="sm" c="dimmed">
          {me.user.email}
          {me.email_verified ? '' : ' (email unverified)'}
        </Text>
      </Group>

      {detail && (
        <Card withBorder maw={560}>
          <Group justify="space-between" mb="xs">
            <Title order={3}>{detail.org.name}</Title>
            <Badge>{detail.role}</Badge>
          </Group>
          {sub ? (
            <Stack gap="xs">
              <Group>
                <Text>Plan: {sub.plan}</Text>
                <Badge color={STATUS_COLOR[sub.status] ?? 'gray'}>{sub.status}</Badge>
              </Group>
              <Text size="sm" c="dimmed">
                {sub.seats} seat{sub.seats === 1 ? '' : 's'}
                {sub.current_period_end &&
                  ` · renews/expires ${new Date(sub.current_period_end).toLocaleDateString()}`}
              </Text>
            </Stack>
          ) : (
            <Text c="dimmed">No subscription yet.</Text>
          )}
          {billingError && (
            <Alert color="red" mt="sm">
              {billingError}
            </Alert>
          )}
          {canBill && (
            <Group mt="md">
              <Button
                variant="light"
                onClick={() =>
                  redirectTo(
                    apiPost<{ url: string }>('/v1/billing/portal', { org_id: detail.org.id }),
                  )
                }
              >
                Manage billing
              </Button>
              <Button
                variant="default"
                onClick={() =>
                  redirectTo(
                    apiPost<{ url: string }>('/v1/billing/checkout', {
                      org_id: detail.org.id,
                      plan: 'pro',
                    }),
                  )
                }
              >
                Buy Pro
              </Button>
            </Group>
          )}
        </Card>
      )}
      <Text size="sm" c="dimmed">
        Licences, appliances and downloads land in the next release waves — this is the
        R5-3 accounts + billing skeleton.
      </Text>
    </Stack>
  );
}

export const Route = createFileRoute('/')({
  component: IndexPage,
});
