/** Shared display helpers for portal pages. */

/** Mantine colour per licence/subscription status. */
export const STATUS_COLOR: Record<string, string> = {
  active: 'green',
  trialing: 'blue',
  past_due: 'yellow',
  expired: 'yellow',
  suspended: 'orange',
  revoked: 'red',
  unpaid: 'red',
  cancelled: 'gray',
};

/** Format a byte count for tables. */
export function formatBytes(n: number): string {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GiB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KiB`;
  return `${n} B`;
}

/** Consistent timestamp display ('—' for null). */
export function formatTime(ts: string | null | undefined): string {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}
