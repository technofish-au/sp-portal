/** Route guards: RequireAuth for customer pages, RequireStaff for /admin. */
import { Alert, Center, Loader, Text } from '@mantine/core';
import { Navigate } from '@tanstack/react-router';
import type { ReactNode } from 'react';
import { useMe } from './me';

export function RequireAuth({ children }: { children: ReactNode }) {
  const me = useMe();
  if (me.isLoading) {
    return (
      <Center mt="xl">
        <Loader />
      </Center>
    );
  }
  if (me.isError) {
    if (me.error.status === 401) {
      return <Navigate to="/login" />;
    }
    return <Alert color="red">Failed to load your account ({me.error.message}).</Alert>;
  }
  return <>{children}</>;
}

export function RequireStaff({ children }: { children: ReactNode }) {
  return (
    <RequireAuth>
      <StaffGate>{children}</StaffGate>
    </RequireAuth>
  );
}

function StaffGate({ children }: { children: ReactNode }) {
  const me = useMe();
  if (!me.data?.user.is_platform_admin) {
    return (
      <Alert color="red" maw={560} mx="auto" mt="xl">
        <Text fw={600}>Staff only</Text>
        This area requires a platform-admin account.
      </Alert>
    );
  }
  return <>{children}</>;
}
