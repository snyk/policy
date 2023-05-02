import { expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures/ignore';
let vulns = require(fixtures + '/vulns.json');

test('ignored vulns do not turn up in tests', async () => {
  const config = await policy.load(fixtures);
  expect(vulns.vulnerabilities).length.greaterThan(0);

  // should strip all
  vulns = config.filter(vulns);
  expect(vulns.ok).toBe(true);
  expect(vulns.vulnerabilities).toStrictEqual([]);
});
