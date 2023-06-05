import cloneDeep from 'lodash.clonedeep';
import { expect, test } from 'vitest';

import * as policy from '../../lib';
import ignore from '../../lib/filter/ignore';
import { Vulnerability } from '../types';

const fixtures = __dirname + '/../fixtures/ignore';
const vulns = require(fixtures + '/vulns.json');

test('ignored vulns do not turn up in tests', async () => {
  const config = await policy.load(fixtures);

  const start = vulns.vulnerabilities.length;
  expect(vulns.vulnerabilities).length.greaterThan(0);

  const filtered = [];

  vulns.vulnerabilities = ignore(
    config.ignore,
    vulns.vulnerabilities,
    filtered
  );

  // should strip 4
  expect(start - 4).toBe(vulns.vulnerabilities.length);
  expect(4).toBe(filtered.length);
  const expected = {
    'npm:hawk:20160119': [
      {
        reason: 'hawk got bumped',
        expires: '2116-03-01T14:30:04.136Z',
        path: ['sqlite', 'sqlite3', 'node-pre-gyp', 'request', 'hawk'],
      },
    ],
    'npm:is-my-json-valid:20160118': [
      {
        reason: 'dev tool',
        expires: '2116-03-01T14:30:04.136Z',
        path: [
          'sqlite',
          'sqlite3',
          'node-pre-gyp',
          'request',
          'har-validator',
          'is-my-json-valid',
        ],
      },
    ],
    'npm:tar:20151103': [
      {
        reason: 'none given',
        expires: '2116-03-01T14:30:04.137Z',
        path: ['sqlite', 'sqlite3', 'node-pre-gyp', 'tar-pack', 'tar'],
      },
    ],
    'npm:marked:20170907': [
      {
        reason: 'none given',
        disregardIfFixable: true,
        path: ['*'],
      },
    ],
  };
  const actual = filtered.reduce((actual, vuln: any) => {
    actual[vuln.id] = vuln.filtered.ignored;
    return actual;
  }, {});
  expect(actual).toStrictEqual(expected);

  expect(
    vulns.vulnerabilities.every((vuln) => {
      return !!vuln.ignored;
    })
  ).toBe(true);
});

test('vulns filtered by security policy ignores', () => {
  const fixturesSecPolicy = __dirname + '/../fixtures/ignore-security-policy';
  const vulns = require(fixturesSecPolicy + '/vulns.json');

  policy.load(fixtures).then(() => {
    const start = vulns.vulnerabilities.length;
    expect(start).toBeGreaterThan(0);

    const filtered = [];

    vulns.vulnerabilities = ignore({}, vulns.vulnerabilities, filtered);

    expect(start - 1).toBe(vulns.vulnerabilities.length);
    expect(filtered).toHaveLength(1);

    const expected = {
      'npm:tar:20151103': [
        {
          reason: '',
          reasonType: 'wont-fix',
          source: 'security-policy',
          ignoredBy: {
            id: '22A6B3BE-ABEF-4407-A634-AB1BE30A552F',
            name: 'Ignored by Security Policy',
          },
          created: '2021-06-13T09:33:57.318Z',
          disregardIfFixable: false,
          path: ['*'],
        },
      ],
    };

    const actual = filtered.reduce((actual, vuln: any) => {
      actual[vuln.id] = vuln.filtered.ignored;
      return actual;
    }, {});

    expect(actual).toStrictEqual(expected);
  });
});

test('vulns filtered by security policy and config ignores', async () => {
  const fixturesSecPolicy = __dirname + '/../fixtures/ignore-security-policy';
  const vulns = require(fixturesSecPolicy + '/vulns-security-metadata.json');

  const config = await policy.load(fixtures);

  const start = vulns.vulnerabilities.length;
  expect(start).toBeGreaterThan(0);

  const filtered = [];

  vulns.vulnerabilities = ignore(
    config.ignore,
    vulns.vulnerabilities,
    filtered
  );

  expect(start - 4).toBe(vulns.vulnerabilities.length);
  expect(filtered).toHaveLength(4);

  const expected = {
    'npm:hawk:20160119': [
      {
        reason: 'hawk got bumped',
        expires: '2116-03-01T14:30:04.136Z',
        path: ['sqlite', 'sqlite3', 'node-pre-gyp', 'request', 'hawk'],
      },
    ],
    'npm:is-my-json-valid:20160118': [
      {
        reason: 'dev tool',
        expires: '2116-03-01T14:30:04.136Z',
        path: [
          'sqlite',
          'sqlite3',
          'node-pre-gyp',
          'request',
          'har-validator',
          'is-my-json-valid',
        ],
      },
    ],
    'npm:tar:20151103': [
      {
        reason: '',
        reasonType: 'wont-fix',
        source: 'security-policy',
        ignoredBy: {
          id: '22A6B3BE-ABEF-4407-A634-AB1BE30A552F',
          name: 'Ignored by Security Policy',
        },
        created: '2021-06-13T09:33:57.318Z',
        disregardIfFixable: false,
        path: ['*'],
      },
    ],
    'npm:marked:20170907': [
      {
        reason: 'none given',
        disregardIfFixable: true,
        path: ['*'],
      },
    ],
  };

  const actual = filtered.reduce((actual, vuln: any) => {
    actual[vuln.id] = vuln.filtered.ignored;
    return actual;
  }, {});

  expect(actual).toStrictEqual(expected);
});

test('does not accept incomplete security policy to ignore vulns', async () => {
  const fixturesSecPolicy = __dirname + '/../fixtures/ignore-security-policy';
  const vulns = require(fixturesSecPolicy +
    '/vulns-incomplete-security-metadata.json');

  const config = await policy.load(fixtures);

  const start = vulns.vulnerabilities.length;
  expect(vulns.vulnerabilities).length.greaterThan(0);

  const filtered = [];

  vulns.vulnerabilities = ignore(
    config.ignore,
    vulns.vulnerabilities,
    filtered
  );

  // should strip 4
  expect(start - 4).toBe(vulns.vulnerabilities.length);
  expect(filtered).toHaveLength(4);
});

test('filters vulnerabilities by exact match', async () => {
  const vulns = {
    vulnerabilities: [
      {
        id: 'a-vuln',
        from: ['dir/file.json', 'foo', 'bar'],
      },
      {
        id: 'a-vuln',
        from: ['file.json', 'foo', 'bar'],
      },
      {
        id: 'another-vuln',
        from: ['file.json', 'foo', 'bar'],
      },
    ] as Vulnerability[],
  };

  const expected = cloneDeep(vulns);
  expected.vulnerabilities.splice(1, 1);

  const config = await policy.load(__dirname + '/../fixtures/ignore-exact');

  const filtered = config.filter(vulns, undefined, 'exact');
  expect(filtered.vulnerabilities).toStrictEqual(expected.vulnerabilities);
});
