import { expect, test } from 'vitest';

import * as policy from '../../lib';
import { VulnerabilityReport } from '../types';

const fixtures = __dirname + '/../fixtures';
const dir = fixtures + '/filter-and-track';
const vulns = require(dir + '/vulns.json') as VulnerabilityReport;

test('filtered vulns can still be reviewed', async () => {
  const p = await policy.load(dir, { loose: true });

  p.skipVerifyPatch = true;
  const res = p.filter(vulns);

  expect(res.ok).toBe(false);

  expect(res.filtered).toBeDefined();
  expect(res.filtered).toBeInstanceOf(Object);
  if (res.filtered === undefined) {
    return;
  }

  expect(res.filtered.ignore).toBeInstanceOf(Array);
  expect(res.filtered.ignore).length.greaterThan(0);
  expect(res.filtered.patch).toBeInstanceOf(Array);
  expect(res.filtered.patch).not.toHaveLength(0);
});
