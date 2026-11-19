import { Alert, Button, Card, Loader, Stack, Switch, Text, Title, Tooltip } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { api, apiPut, type NotificationPrefs } from '../api';
import { RequireAuth } from '../auth';
import { useCurrentOrg } from '../me';

function NotificationsPage() {
  const org = useCurrentOrg();
  const queryClient = useQueryClient();
  const prefs = useQuery({
    queryKey: ['notification-prefs', org?.org.id],
    enabled: !!org,
    queryFn: () =>
      api<{ prefs: NotificationPrefs }>(`/v1/organisations/${org!.org.id}/notification-prefs`),
  });
  // draft holds local edits; once the server copy is the truth again it
  // resets to null so current falls back to the query data.
  const [draft, setDraft] = useState<NotificationPrefs | null>(null);
  const current = draft ?? prefs.data?.prefs;

  const save = useMutation({
    mutationFn: (p: NotificationPrefs) =>
      apiPut(`/v1/organisations/${org!.org.id}/notification-prefs`, p),
    onSuccess: () => {
      setDraft(null);
      void queryClient.invalidateQueries({ queryKey: ['notification-prefs', org?.org.id] });
    },
  });

  const toggle = (key: keyof NotificationPrefs) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setDraft(current ? { ...current, [key]: e.currentTarget.checked } : null);

  return (
    <Stack gap="md" maw={560}>
      <Title order={1}>Notifications</Title>
      <Text c="dimmed">
        Email notifications for {org?.org.name}. These preferences apply to your account only.
      </Text>
      {prefs.isLoading && <Loader />}
      {prefs.isError && <Alert color="red">Failed to load preferences.</Alert>}
      {save.isSuccess && <Alert color="green">Preferences saved.</Alert>}
      {save.isError && <Alert color="red">Save failed: {save.error.message}</Alert>}
      {current && (
        <Card withBorder>
          <Stack gap="sm">
            <Switch
              label="Instance behind on versions"
              description="Email when an appliance is two or more minor versions behind the latest release."
              checked={current.notify_version_behind}
              onChange={toggle('notify_version_behind')}
            />
            <Switch
              label="Security releases"
              description="Email when a security release applies to your appliances."
              checked={current.notify_security_release}
              onChange={toggle('notify_security_release')}
            />
            <Switch
              label="Licence expiry"
              description="Email when a licence nears its expiry date."
              checked={current.notify_licence_expiry}
              onChange={toggle('notify_licence_expiry')}
            />
            <Tooltip label="Billing-failure mail cannot be switched off.">
              <Switch
                label="Billing"
                description="Payment failures and invoice notices — always on."
                checked
                disabled
              />
            </Tooltip>
            <Button
              mt="sm"
              onClick={() => save.mutate({ ...current, notify_billing: true })}
              loading={save.isPending}
            >
              Save preferences
            </Button>
          </Stack>
        </Card>
      )}
    </Stack>
  );
}

export const Route = createFileRoute('/notifications')({
  component: () => (
    <RequireAuth>
      <NotificationsPage />
    </RequireAuth>
  ),
});
