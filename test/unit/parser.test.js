const test = require('tap-only');
const parser = require('../../lib/parser');
const fixtures = __dirname + '/../fixtures';
const yaml = require('js-yaml');

test('parser fills out defaults', function (t) {
  const res = parser.import();
  const expect = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
  };

  t.deepEqual(res, expect, 'parser fills defaults');
  t.end();
});

test('parser fills out defaults for invalid inputs', function (t) {
  const res = parser.import('test');
  const expect = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
  };

  t.deepEqual(res, expect, 'parser fills defaults for invalid inputs');
  t.end();
});

test('parser does not modify default parsed format', function (t) {
  const expect = {
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

  const res = parser.import(yaml.safeDump(expect));

  t.deepEqual(res, expect, 'parser does nothing extra (v1 vs v1)');
  t.end();
});

test('test unsupported version', function (t) {
  t.throws(
    function () {
      parser.import(
        yaml.safeDump({
          version: 'v20.0.1',
        })
      );
    },
    /unsupported version/,
    'unsupported version throws'
  );
  t.end();
});

test('demunge', function (t) {
  const source = require(fixtures + '/parsed.json');
  const res = parser.demunge(source);
  const patchIds = Object.keys(source.patch);
  const ignoreIds = Object.keys(source.ignore);
  const excludeIds = Object.keys(source.exclude);
  t.ok(Array.isArray(res.ignore), 'array');
  t.ok(Array.isArray(res.patch), 'array');
  t.ok(Array.isArray(res.exclude), 'array');
  t.equal(res.patch.length, 2, 'two patched items');
  t.equal(res.ignore.length, 3, 'three ignored items');
  t.equal(res.exclude.length, 2, 'two excluded categories');
  t.deepEqual(
    res.patch.map(function (o) {
      return o.id;
    }),
    patchIds,
    'patch ids found in the right place'
  );
  t.deepEqual(
    res.ignore.map(function (o) {
      return o.id;
    }),
    ignoreIds,
    'ignore ids found in the right place'
  );
  t.deepEqual(
    res.exclude.map(function (o) {
      return o.id;
    }),
    excludeIds,
    'exclude ids found in the right place'
  );
  t.end();
});
