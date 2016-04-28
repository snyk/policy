var test = require('tap').test;
var Promise = require('es6-promise').Promise; // jshint ignore:line
var fixtures = __dirname + '/../fixtures/patch';
var vulns = require(fixtures + '/vulns.json');
var proxyquire = require('proxyquire');
var policy = require('../../');
var patch = proxyquire('../../lib/filter/patch', {
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
  policy.load(fixtures).then(function (config) {
    var start = vulns.vulnerabilities.length;
    t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');

    vulns.vulnerabilities = patch(
      config.patch,
      vulns.vulnerabilities,
      fixtures
    );

    // should strip 2

    t.equal(start - 2, vulns.vulnerabilities.length, 'post filter');
  }).catch(t.threw).then(t.end);
});
