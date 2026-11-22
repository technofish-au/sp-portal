/**
 * Pricing data — PLACEHOLDER PRICES.
 *
 * The licence tiers and limits below are the agreed structure
 * (per-managed-machine tiers, monthly/annual billing, annual-invoice
 * enterprise option), but the amounts are provisional and marked as such on
 * the rendered page. When final pricing is decided, edit ONLY this file.
 *
 * Amounts are in AUD cents per month (monthly billing) or AUD cents per year
 * (annual billing), ex GST — Stripe Tax adds GST at checkout.
 */

export interface Tier {
  id: string;
  name: string;
  /** Managed machines covered by the tier. */
  maxMachines: number;
  /** AUD cents per month, billed monthly. PLACEHOLDER. */
  monthlyCents: number;
  /** AUD cents per year, billed annually. PLACEHOLDER. */
  annualCents: number;
  blurb: string;
}

export const CURRENCY = 'AUD';
export const CURRENCY_SYMBOL = 'A$';
export const PRICES_ARE_PLACEHOLDER = true;

export const TIERS: Tier[] = [
  {
    id: 'perch-100',
    name: 'Perch 100',
    maxMachines: 100,
    monthlyCents: 14900,
    annualCents: 149000,
    blurb: 'Small estates and single-site teams.',
  },
  {
    id: 'perch-500',
    name: 'Perch 500',
    maxMachines: 500,
    monthlyCents: 44900,
    annualCents: 449000,
    blurb: 'Growing fleets across several sites.',
  },
  {
    id: 'perch-2000',
    name: 'Perch 2,000',
    maxMachines: 2000,
    monthlyCents: 99900,
    annualCents: 999000,
    blurb: 'Large estates and MSP-style operations.',
  },
  {
    id: 'perch-5000',
    name: 'Perch 5,000',
    maxMachines: 5000,
    monthlyCents: 199900,
    annualCents: 1999000,
    blurb: 'Very large estates; talk to us beyond this.',
  },
];

/** Annual-billing effective discount vs monthly (used for the "save" note). */
export function annualSavingPercent(t: Tier): number {
  return Math.round((1 - t.annualCents / (t.monthlyCents * 12)) * 100);
}

export function formatCents(cents: number): string {
  const dollars = cents / 100;
  return dollars.toLocaleString('en-AU', { maximumFractionDigits: 0 });
}

/** Enterprise / purchase-order option (annual invoice, net 30). */
export const ENTERPRISE = {
  name: 'Enterprise',
  blurb:
    'Annual invoice billing (net 30) for organisations that need a purchase order, ' +
    'custom machine counts, or offline/air-gapped licensing.',
};
