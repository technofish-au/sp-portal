/** Tiny same-origin fetch wrapper for the /v1 API. */

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
    ...init,
  });
  if (res.status === 204) {
    return undefined as T;
  }
  const body = (await res.json().catch(() => ({}))) as {
    error?: string;
    message?: string;
  };
  if (!res.ok) {
    throw new ApiError(res.status, body.error ?? 'error', body.message ?? res.statusText);
  }
  return body as T;
}

export function apiPost<T>(path: string, payload: unknown): Promise<T> {
  return api<T>(path, { method: 'POST', body: JSON.stringify(payload) });
}

export function apiPut<T>(path: string, payload: unknown): Promise<T> {
  return api<T>(path, { method: 'PUT', body: JSON.stringify(payload) });
}

export function apiPatch<T>(path: string, payload: unknown): Promise<T> {
  return api<T>(path, { method: 'PATCH', body: JSON.stringify(payload) });
}

export function apiDelete<T>(path: string): Promise<T> {
  return api<T>(path, { method: 'DELETE' });
}

export interface PublicUser {
  id: string;
  email: string;
  display_name: string;
  totp_enabled: boolean;
  is_platform_admin: boolean;
}

export interface OrgView {
  org: { id: string; name: string; slug: string };
  role: string;
}

export interface MeResponse {
  user: PublicUser;
  email_verified: boolean;
  organisations: OrgView[];
}

export interface Subscription {
  id: string;
  plan: string;
  status: string;
  seats: number;
  current_period_end: string | null;
}

export interface OrgDetail {
  org: { id: string; name: string; slug: string };
  role: string;
  subscription?: Subscription;
}

/** computed licence status from the API */
export type LicenceStatus = 'active' | 'expired' | 'revoked';

export interface Licence {
  id: string;
  org_id: string;
  licence_key: string;
  kind: string;
  plan: string;
  max_instances: number;
  seats_used: number;
  status: LicenceStatus;
  doc_issued: boolean;
  doc_hash: string;
  issued_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface Instance {
  id: string;
  org_id: string;
  licence_id: string | null;
  licence_key: string;
  name: string;
  instance_id: string;
  appliance_version: string;
  status: string;
  suspected_clone: boolean;
  last_seen_at: string | null;
  created_at: string;
}

export interface InstanceReport {
  id: string;
  reported_at: string;
  payload: Record<string, unknown>;
}

export interface Release {
  id: string;
  version: string;
  component: string;
  channel: string;
  notes: string;
  min_upgrade_from: string;
  security: boolean;
  artifact_path: string;
  sha256: string;
  size_bytes: number;
  published: boolean;
  published_at: string | null;
  withdrawn_at: string | null;
  created_at: string;
}

export interface DownloadURL {
  url: string;
  expires_at: string;
  release: { id: string; version: string; component: string; sha256: string; size_bytes: number };
}

export interface Member {
  id: string;
  email: string;
  display_name: string;
  role: string;
}

export interface NotificationPrefs {
  notify_version_behind: boolean;
  notify_security_release: boolean;
  notify_licence_expiry: boolean;
  notify_billing: boolean;
}

// --- staff admin views ----------------------------------------------------

export interface AdminOrg {
  id: string;
  name: string;
  slug: string;
  billing_email: string;
  tax_id: string;
  stripe_customer_id: string | null;
  created_at: string;
}

export interface AdminUser {
  id: string;
  email: string;
  display_name: string;
  is_platform_admin: boolean;
  totp_enabled: boolean;
  email_verified: boolean;
  disabled_at: string | null;
  created_at: string;
}

export interface SearchResults {
  organisations: AdminOrg[];
  users: AdminUser[];
  licences: Licence[];
  instances: Instance[];
}

export interface AdminOrgDetail {
  org: AdminOrg;
  members: Member[];
  licences: Licence[];
  instances: Instance[];
  subscription: Subscription | null;
}

export interface EstateTotals {
  organisations: number;
  users: number;
  live_licences: number;
  active_instances: number;
  suspected_clones: number;
  seen_24h: number;
  seen_7d: number;
  stale_7d: number;
}

export interface Estate {
  totals: EstateTotals;
  versions: { appliance_version: string; instances: number }[];
}

export interface AuditEntry {
  id: string;
  org_id: string | null;
  actor_user_id: string | null;
  actor_email: string;
  action: string;
  target_type: string;
  target_id: string;
  detail: unknown;
  ip: string;
  created_at: string;
}
