var test = require('tap').test;
var Promise = require('es6-promise').Promise; // jshint ignore:line
var fixtures = __dirname + '/../fixtures/ignore';
var vulns = require(fixtures + '/vulns.json');

var policy = require('../../');

test('ignored vulns do not turn up in tests', function (t) {
  return policy.load(fixtures).then(function (config) {
    t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');

    // should strip all
    vulns = config.filter(vulns);
    t.equal(vulns.ok, true, 'post filter, we have no vulns');
    t.deepEqual(vulns.vulnerabilities, [], 'vulns stripped');
  });
});
