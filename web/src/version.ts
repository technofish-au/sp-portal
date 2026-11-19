/** Loose semver compare for appliance/release versions ("1.4.2-rc1"). */

function parse(v: string): number[] {
  const core = v.split(/[-+]/, 1)[0] ?? '';
  return core.split('.').map((p) => {
    const n = Number.parseInt(p, 10);
    return Number.isNaN(n) ? 0 : n;
  });
}

/** compareVersions returns <0 when a<b, 0 when equal, >0 when a>b. */
export function compareVersions(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}
