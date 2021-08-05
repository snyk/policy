const cloneDeep = require('lodash.clonedeep');
const test = require('tap').test;
const fixtures = __dirname + '/../fixtures/ignore';
const vulns = require(fixtures + '/vulns.json');

const policy = require('../../');
const ignore = require('../../lib/filter/ignore');

test('ignored vulns do not turn up in tests', function (t) {
  policy
    .load(fixtures)
    .then(function (config) {
      const start = vulns.vulnerabilities.length;
      t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');

      const filtered = [];

      vulns.vulnerabilities = ignore(
        config.ignore,
        vulns.vulnerabilities,
        filtered
      );

      // should strip 4
      t.equal(
        start - 4,
        vulns.vulnerabilities.length,
        'post filter: ' + vulns.vulnerabilities.length
      );
      t.equal(4, filtered.length, '4 vulns filtered');
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
      const actual = filtered.reduce(function (actual, vuln) {
        actual[vuln.id] = vuln.filtered.ignored;
        return actual;
      }, {});
      t.same(actual, expected, 'filtered vulns include ignore rules');

      t.notEqual(
        vulns.vulnerabilities.every(function (vuln) {
          return !!vuln.ignored;
        }),
        'vulns do not have ignored property'
      );
    })
    .catch(t.threw)
    .then(t.end);
});

test('vulns filtered by security policy ignores', function (t) {
  const fixturesSecPolicy = __dirname + '/../fixtures/ignore-security-policy';
  const vulns = require(fixturesSecPolicy + '/vulns.json');

  policy
    .load(fixtures)
    .then(function () {
      const start = vulns.vulnerabilities.length;
      t.ok(start > 0, `we have ${start} vulns to start with`);

      const filtered = [];

      vulns.vulnerabilities = ignore({}, vulns.vulnerabilities, filtered);

      t.equal(
        start - 1,
        vulns.vulnerabilities.length,
        `vulns that were not filtered: ${vulns.vulnerabilities.length}`
      );
      t.equal(1, filtered.length, `${filtered.length} vuln filtered`);

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

      const actual = filtered.reduce(function (actual, vuln) {
        actual[vuln.id] = vuln.filtered.ignored;
        return actual;
      }, {});

      t.same(actual, expected, 'filtered vuln includes ignore rules');
    })
    .catch(t.threw)
    .then(t.end);
});

test('vulns filtered by security policy and config ignores', function (t) {
  const fixturesSecPolicy = __dirname + '/../fixtures/ignore-security-policy';
  const vulns = require(fixturesSecPolicy + '/vulns-security-metadata.json');

  policy
    .load(fixtures)
    .then(function (config) {
      const start = vulns.vulnerabilities.length;
      t.ok(start > 0, `we have ${start} vulns to start with`);

      const filtered = [];

      vulns.vulnerabilities = ignore(
        config.ignore,
        vulns.vulnerabilities,
        filtered
      );

      t.equal(
        start - 4,
        vulns.vulnerabilities.length,
        `vulns that were not filtered: 0`
      );

      t.equal(filtered.length, 4, `${filtered.length} vuln filtered`);

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

      const actual = filtered.reduce(function (actual, vuln) {
        actual[vuln.id] = vuln.filtered.ignored;
        return actual;
      }, {});

      t.same(
        actual,
        expected,
        'filtered vuln includes ignore rules from security policies and config'
      );
    })
    .catch(t.threw)
    .then(t.end);
});

test('does not accept incomplete security policy to ignore vulns', function (t) {
  const fixturesSecPolicy = __dirname + '/../fixtures/ignore-security-policy';
  const vulns = require(fixturesSecPolicy +
    '/vulns-incomplete-security-metadata.json');

  policy
    .load(fixtures)
    .then(function (config) {
      const start = vulns.vulnerabilities.length;
      t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');

      const filtered = [];

      vulns.vulnerabilities = ignore(
        config.ignore,
        vulns.vulnerabilities,
        filtered
      );

      // should strip 4
      t.equal(
        start - 4,
        vulns.vulnerabilities.length,
        'vulns that were not filtered: ' + vulns.vulnerabilities.length
      );
      t.equal(4, filtered.length, '4 vulns filtered');
    })
    .catch(t.threw)
    .then(t.end);
});

test('filters vulnerabilities by exact match', function (t) {
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
    ],
  };

  const expected = cloneDeep(vulns);
  expected.vulnerabilities.splice(1, 1);

  policy
    .load(__dirname + '/../fixtures/ignore-exact')
    .then(function (config) {
      const filtered = config.filter(vulns, undefined, 'exact');
      t.same(filtered.vulnerabilities, expected.vulnerabilities);
    })
    .catch(t.threw)
    .then(t.end);
});
