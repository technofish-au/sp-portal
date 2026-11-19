import { AppShell, Button, Group, Text, Title } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { createRootRoute, Link, Outlet, useNavigate } from '@tanstack/react-router';
import { apiPost } from '../api';
import { useMe } from '../me';

const NAV = [
  { to: '/', label: 'Dashboard' },
  { to: '/licences', label: 'Licences' },
  { to: '/instances', label: 'Instances' },
  { to: '/downloads', label: 'Downloads' },
  { to: '/team', label: 'Team' },
  { to: '/notifications', label: 'Notifications' },
] as const;

/** Root layout: app shell + top nav once a session is present. */
function RootLayout() {
  const me = useMe();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const signedIn = !!me.data && !me.isError;

  async function logout() {
    await apiPost('/v1/auth/logout', {}).catch(() => undefined);
    queryClient.clear();
    await navigate({ to: '/login' });
  }

  return (
    <AppShell header={{ height: 56 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="lg" wrap="nowrap">
            <Title order={3}>ServerPerch</Title>
            {signedIn &&
              NAV.map((item) => (
                <Button
                  key={item.to}
                  component={Link}
                  to={item.to}
                  variant="subtle"
                  size="compact-sm"
                >
                  {item.label}
                </Button>
              ))}
            {signedIn && me.data?.user.is_platform_admin && (
              <Button component={Link} to="/admin" variant="subtle" size="compact-sm" color="grape">
                Staff admin
              </Button>
            )}
          </Group>
          <Group gap="sm" wrap="nowrap">
            {signedIn ? (
              <>
                <Text size="sm" c="dimmed" visibleFrom="sm">
                  {me.data?.user.email}
                </Text>
                <Button size="compact-sm" variant="default" onClick={logout}>
                  Sign out
                </Button>
              </>
            ) : (
              <Text size="sm" c="dimmed">
                customer portal
              </Text>
            )}
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}

export const Route = createRootRoute({
  component: RootLayout,
});
