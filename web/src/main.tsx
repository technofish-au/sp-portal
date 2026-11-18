import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

import { RouterProvider } from '@tanstack/react-router';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createAppInstance } from './app';
import { AppProviders } from './AppProviders';

const { queryClient, router } = createAppInstance({
  queryClientConfig: { defaultOptions: { queries: { staleTime: 10_000, retry: 1 } } },
});

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('missing #root element');
}

createRoot(rootElement).render(
  <StrictMode>
    <AppProviders queryClient={queryClient}>
      <RouterProvider router={router} />
    </AppProviders>
  </StrictMode>,
);
