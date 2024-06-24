import * as yaml from 'js-yaml';
import { expect, test } from 'vitest';
import * as parser from '../../lib/parser';

const fixtures = __dirname + '/../fixtures';

test('parser fills out defaults', () => {
  const res = parser.import();
  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
  };

  expect(res).toStrictEqual(expected);
});

test('parser fills out defaults for invalid inputs', () => {
  const res = parser.import('test');
  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
  };

  expect(res).toStrictEqual(expected);
});

test('parser fills out defaults for invalid array input', () => {
  const res = parser.import(
    `# Snyk (https://snyk.io) policy file, patches or ignores known vulnerabilities.+
    - object Object`,
  );
  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
  };

  expect(res).toStrictEqual(expected);
});

test('parser does not modify default parsed format', () => {
  const expected = {
    version: 'v1.0.0',
    patch: {
      'glue > hapi > joi > moment': [
        {
          patched: '2016-02-26T16:19:06.050Z',
        },
      ],
    },
    ignore: {},
  };

  const res = parser.import(yaml.dump(expected));

  expect(res).toStrictEqual(expected);
});

test('test unsupported version', () => {
  expect(() => {
    parser.import(
      yaml.dump({
        version: 'v20.0.1',
      }),
    );
  }).toThrow(/unsupported version/);
});

test('demunge returns expected result', () => {
  const source = require(fixtures + '/parsed.json');
  const res = parser.demunge(source);
  const patchIds = Object.keys(source.patch);
  const ignoreIds = Object.keys(source.ignore);
  const excludeIds = Object.keys(source.exclude);

  expect(res.ignore).toBeInstanceOf(Array);
  expect(res.patch).toBeInstanceOf(Array);
  expect(res.exclude).toBeInstanceOf(Array);
  expect(res.patch).toHaveLength(2);
  expect(res.ignore).toHaveLength(3);
  expect(res.exclude).toHaveLength(2);

  expect(res.patch.map((o) => o.id)).toStrictEqual(patchIds);
  expect(res.ignore.map((o) => o.id)).toStrictEqual(ignoreIds);
  expect(res.exclude.map((o) => o.id)).toStrictEqual(excludeIds);
});

test('demunge returns correct license vuln urls when apiRoot func provided', () => {
  const source = require(fixtures + '/parsed.json');

  function apiRoot(vulnId: string) {
    const match = new RegExp(/^snyk:lic/i).test(vulnId);
    if (match) {
      return 'https://snyk.io';
    }
    return 'https://security.snyk.io';
  }
  const res = parser.demunge(source, apiRoot);

  expect(res.ignore[0].url).toBe(
    'https://snyk.io/vuln/snyk:lic:npm:shescape:MPL-2.0',
  );
  expect(res.ignore[1].url).toBe(
    'https://security.snyk.io/vuln/npm:is-my-json-valid:20160118',
  );
});

test('demunge returns urls when no apiRoot arg', () => {
  const source = require(fixtures + '/parsed.json');

  const res = parser.demunge(source);

  expect(res.ignore[0].url).toBe('/vuln/snyk:lic:npm:shescape:MPL-2.0');
});
