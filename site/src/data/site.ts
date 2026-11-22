/**
 * Central site data — single source of truth for anything that changes
 * (URLs, contact addresses, trial terms). Pages and components import from
 * here; do not hard-code these values in markup.
 */

/** Customer portal (sp-portal SPA served at portal.serverperch.com). */
export const PORTAL = {
  /** Portal dashboard — also the buy/upgrade entry point ("Buy" creates a
   *  Stripe Checkout session from the dashboard once signed in). */
  root: 'https://portal.serverperch.com/',
  /** Self-service sign-up; creates the org + trial licence. */
  signup: 'https://portal.serverperch.com/signup',
  /** Sign-in for existing customers. */
  login: 'https://portal.serverperch.com/login',
};

/** Trial terms — mirror the portal's sign-up defaults. */
export const TRIAL = {
  days: 30,
  machines: 25,
};

/**
 * Documentation home. A versioned public docs site is planned but not yet
 * published; until it exists, operator docs ship inside the appliance and in
 * the sp-platform repository. Keep this constant so the switch is one edit.
 */
export const DOCS_URL = 'https://serverperch.com/docs/';

export const CONTACT = {
  sales: 'sales@serverperch.com',
  support: 'support@serverperch.com',
  security: 'security@serverperch.com',
};
