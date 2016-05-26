var test = require('tap').test;
var Promise = require('es6-promise').Promise; // jshint ignore:line
var fixtures = __dirname + '/../fixtures/ignore-expired';
var vulns = require(fixtures + '/vulns.json');

var policy = require('../../');

test('expired policies do not strip', function (t) {
  return policy.load(fixtures).then(function (config) {
    var start = vulns.vulnerabilities.length;
    t.ok(start > 0, 'we have vulns to start with');

    // should strip all
    vulns = config.filter(vulns);
    var filtered = config.stripFiltered(vulns);

    t.equal(vulns.ok, false, 'post filter, we still have vulns');
    t.equal(filtered.vulnerabilities.length, start, 'all vulns remained');
  });
});
