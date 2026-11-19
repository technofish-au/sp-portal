/** Shared staff-admin sub-navigation. */
import { Badge, Group } from '@mantine/core';
import { Link } from '@tanstack/react-router';

const ADMIN_NAV = [
  { to: '/admin', label: 'Search + estate' },
  { to: '/admin/releases', label: 'Release catalogue' },
  { to: '/admin/audit', label: 'Audit log' },
] as const;

export function AdminNav() {
  return (
    <Group gap="xs">
      {ADMIN_NAV.map((n) => (
        <Badge
          key={n.to}
          variant="light"
          component={Link}
          to={n.to}
          style={{ cursor: 'pointer' }}
        >
          {n.label}
        </Badge>
      ))}
    </Group>
  );
}
