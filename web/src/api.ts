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

export interface PublicUser {
  id: string;
  email: string;
  display_name: string;
  totp_enabled: boolean;
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
