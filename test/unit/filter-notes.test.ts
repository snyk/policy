import { expect, test } from 'vitest';

import { FilteredVulnerabilityReport } from '../types';
import * as policy from '../../lib';
import notes from '../../lib/filter/notes';

const fixtures = __dirname + '/../fixtures';
const vulns = require(fixtures +
  '/patch/vulns.json') as FilteredVulnerabilityReport;

test('ignored vulns do not turn up in tests', async () => {
  const res = await policy.load([
    fixtures + '/patch',
    fixtures + '/deep-policy',
  ]);

  const start = vulns.vulnerabilities.length;
  expect(vulns.vulnerabilities).length.greaterThan(0);
  expect(res.suggest).toBeTruthy();

  // FIXME patch vulns doesn't match anything in the ignore/.snyk
  vulns.vulnerabilities = notes(res.suggest, vulns.vulnerabilities);

  expect(start).toBe(vulns.vulnerabilities.length);

  const items = vulns.vulnerabilities.map((e) => e.note).filter(Boolean);

  expect(items).toHaveLength(1);
  expect(items[0]).not.toMatch(new RegExp('undefined'));
});
