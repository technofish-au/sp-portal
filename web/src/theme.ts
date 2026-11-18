import { createTheme } from '@mantine/core';

/** ServerPerch Portal Mantine theme. Light/dark follow the OS (defaultColorScheme="auto"). */
export const theme = createTheme({
  primaryColor: 'indigo',
  defaultRadius: 'md',
  focusRing: 'auto',
  fontFamily:
    'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  fontFamilyMonospace:
    'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
  headings: { fontWeight: '600' },
});
