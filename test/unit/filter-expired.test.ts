import { expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures/ignore-expired';
const fixturesNoQuotes = __dirname + '/../fixtures/ignore-expired-no-quotes';
const fixturesInvalidExpiry = __dirname + '/../fixtures/ignore-invalid-expiry';
let vulns = require(fixtures + '/vulns.json');

test('expired policies do not strip', async () => {
  const config = await policy.load(fixtures);
  const start = vulns.vulnerabilities.length;
  expect(start).toBeGreaterThan(0);

  // should keep all vulns, because all of the ignores expired
  vulns = config.filter(vulns);
  expect(vulns.ok).toBe(false);
  expect(vulns.vulnerabilities).toHaveLength(start);
});

test('expired policies do not strip (no quotes)', () => {
  return policy.load(fixturesNoQuotes).then((config) => {
    const start = vulns.vulnerabilities.length;
    expect(start).toBeGreaterThan(0);

    // should keep all vulns, because all of the ignores expired
    vulns = config.filter(vulns);
    expect(vulns.ok).toBe(false);
    expect(vulns.vulnerabilities).toHaveLength(start);
  });
});

test('invalid expiry are stripped', () => {
  return policy.load(fixturesInvalidExpiry).then((config) => {
    const vulnsCount = vulns.vulnerabilities.length;
    expect(vulnsCount).toBeGreaterThan(0);

    // should keep all vulns, because all of the ignores have invalid expiry date
    const result = config.filter(vulns);
    expect(result.ok).toBe(false);
    expect(result.vulnerabilities).toHaveLength(vulnsCount);
    expect(result.filtered.ignore).toHaveLength(0);
  });
});
