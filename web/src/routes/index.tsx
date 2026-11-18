import { Stack, Text, Title } from '@mantine/core';
import { createFileRoute } from '@tanstack/react-router';

function IndexPage() {
  return (
    <Stack gap="xs">
      <Title order={1}>Welcome to ServerPerch Portal</Title>
      <Text c="dimmed">
        Licences, appliances and downloads for your ServerPerch deployment. The portal is under
        construction — domain pages land in the next release waves.
      </Text>
    </Stack>
  );
}

export const Route = createFileRoute('/')({
  component: IndexPage,
});
