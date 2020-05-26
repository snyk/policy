const test = require('tap').test;
const fixtures = __dirname + '/../fixtures/patch';
const vulns = require(fixtures + '/vulns.json');
const proxyquire = require('proxyquire');
const policy = require('../../');
const patch = proxyquire('../../lib/filter/patch', {
  './get-vuln-source': proxyquire('../../lib/filter/get-vuln-source', {
    'snyk-resolve': {
      sync: function () {
        return '.';
      },
    },
    fs: {
      statSync: function () {
        throw new Error('nope');
      },
    },
  }),
  fs: {
    statSync: function () {
      return true;
    },
  },
});

test('patched vulns do not turn up in tests', function (t) {
  policy
    .load(fixtures)
    .then(function (config) {
      const start = vulns.vulnerabilities.length;
      t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');

      const filtered = [];

      vulns.vulnerabilities = patch(
        config.patch,
        vulns.vulnerabilities,
        fixtures,
        true,
        filtered
      );

      // should strip 3

      t.equal(start - 3, vulns.vulnerabilities.length, 'post filter');
      t.equal(3, filtered.length, '3 vulns filtered');

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
      const actual = filtered.reduce(function (actual, vuln) {
        actual[vuln.id] = vuln.filtered.patches;
        return actual;
      }, {});
      t.same(actual, expected, 'filtered vulns include patch rules');

      t.notEqual(
        vulns.vulnerabilities.every(function (vuln) {
          return !!vuln.patches;
        }),
        'vulns do not have patches property'
      );
    })
    .catch(t.threw)
    .then(t.end);
});
