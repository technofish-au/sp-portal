import { QueryClient, type QueryClientConfig } from '@tanstack/react-query';
import { createRouter } from './router';

export interface AppInstance {
  queryClient: QueryClient;
  router: ReturnType<typeof createRouter>;
}

export interface AppOptions {
  queryClientConfig?: QueryClientConfig;
}

/** Build the app-wide singletons (query client, router). */
export function createAppInstance(options: AppOptions = {}): AppInstance {
  const queryClient = new QueryClient(options.queryClientConfig);
  return { queryClient, router: createRouter() };
}
