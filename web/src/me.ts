/** Session helpers shared across portal pages. */
import { useQuery } from '@tanstack/react-query';
import { api, type ApiError, type MeResponse, type OrgView } from './api';

/** Fetch the current session user + org memberships. */
export function useMe() {
  return useQuery<MeResponse, ApiError>({
    queryKey: ['me'],
    queryFn: () => api<MeResponse>('/v1/auth/me'),
    staleTime: 30_000,
    retry: (count, err) => {
      // Never retry auth failures — they mean "go sign in".
      if (err.status === 401 || err.status === 403) return false;
      return count < 2;
    },
  });
}

/** The portal is single-org today: the first membership is the current org. */
export function useCurrentOrg(): OrgView | undefined {
  const { data } = useMe();
  return data?.organisations[0];
}
