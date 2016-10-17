var test = require('tap').test;
var Promise = require('es6-promise').Promise; // jshint ignore:line
var fixtures = __dirname + '/../fixtures/ignore';
var vulns = require(fixtures + '/vulns.json');

var policy = require('../../');
var ignore = require('../../lib/filter/ignore');

test('ignored vulns do not turn up in tests', function (t) {
  policy.load(fixtures).then(function (config) {
    var start = vulns.vulnerabilities.length;
    t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');

    var filtered = [];

    vulns.vulnerabilities = ignore(
      config.ignore,
      vulns.vulnerabilities,
      filtered
    );

    // should strip 3
    t.equal(start - 3, vulns.vulnerabilities.length, 'post filter: ' + vulns.vulnerabilities.length);
    t.equal(3, filtered.length, filtered.length + ' vulns filtered');
    t.equal(filtered[0].ignore.reason, 'hawk got bumped', 'filtered vuln has ignore info');
  }).catch(t.threw).then(t.end);
});
