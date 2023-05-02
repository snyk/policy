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
      })
    );
  }).toThrow(/unsupported version/);
});

test('demunge', () => {
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
