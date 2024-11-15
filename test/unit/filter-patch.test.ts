import fs from 'fs';
import resolve from 'snyk-resolve';
import { afterEach, expect, test, vi } from 'vitest';

import * as policy from '../../lib';
import patch from '../../lib/filter/patch';
import {
  FilteredRule,
  FilteredVulnerability,
  VulnerabilityReport,
} from '../types';

const fixtures = __dirname + '/../fixtures/patch';
const vulns = require(fixtures + '/vulns.json') as VulnerabilityReport;

afterEach(() => {
  vi.resetAllMocks();
});

test('patched vulns do not turn up in tests', async () => {
  vi.spyOn(fs, 'statSync').mockReturnValueOnce(new fs.Stats());
  vi.spyOn(resolve, 'sync').mockReturnValueOnce('.');

  const config = await policy.load(fixtures);

  const start = vulns.vulnerabilities.length;
  expect(vulns.vulnerabilities).length.greaterThan(0);

  const filtered = [] as FilteredVulnerability[];

  vulns.vulnerabilities = patch(
    config.patch,
    vulns.vulnerabilities,
    fixtures,
    true,
    filtered,
  );

  // should strip 3

  expect(start - 3).toBe(vulns.vulnerabilities.length);
  expect(filtered).toHaveLength(3);

  const expected = {
    'npm:uglify-js:20150824': [
      {
        patched: '2016-03-03T18:06:06.091Z',
        path: ['jade', 'transformers', 'uglify-js'],
      },
    ],
    'npm:uglify-js:20151024': [
      {
        patched: '2016-03-03T18:06:06.091Z',
        path: ['jade', 'transformers', 'uglify-js'],
      },
    ],
    'npm:semver:20150403': [{ path: ['*'] }],
  };

  const actual = filtered.reduce(
    (actual, vuln) => {
      actual[vuln.id] = vuln.filtered?.patches;
      return actual;
    },
    {} as Record<string, FilteredRule[] | undefined>,
  );

  expect(actual).toStrictEqual(expected);
  expect(vulns.vulnerabilities.every((vuln) => !!vuln.patches)).toBe(true);
});
