import { AppShell, Group, Text, Title } from '@mantine/core';
import { createRootRoute, Outlet } from '@tanstack/react-router';

/** Root layout: minimal app shell the domain routes render inside. */
function RootLayout() {
  return (
    <AppShell header={{ height: 56 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Title order={3}>ServerPerch</Title>
          <Text size="sm" c="dimmed">
            customer portal
          </Text>
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
