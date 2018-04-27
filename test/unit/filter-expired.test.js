var test = require('tap').test;
var fixtures = __dirname + '/../fixtures/ignore-expired';
var fixturesNoQuotes = __dirname + '/../fixtures/ignore-expired-no-quotes';
var vulns = require(fixtures + '/vulns.json');

var policy = require('../../');
var notes = require('../../lib/filter/notes');

test('expired policies do not strip', function (t) {
  return policy.load(fixtures).then(function (config) {
    var start = vulns.vulnerabilities.length;
    t.ok(start > 0, 'we have vulns to start with');

    // should keep all vulns, because all of the ignores expired
    vulns = config.filter(vulns);
    t.equal(vulns.ok, false, 'post filter, we still have vulns');
    t.equal(vulns.vulnerabilities.length, start, 'all vulns remained');
  });
});

test('expired policies do not strip (no quotes)', function (t) {
  return policy.load(fixturesNoQuotes).then(function (config) {
    var start = vulns.vulnerabilities.length;
    t.ok(start > 0, 'we have vulns to start with');

    // should keep all vulns, because all of the ignores expired
    vulns = config.filter(vulns);
    t.equal(vulns.ok, false, 'post filter, we still have vulns');
    t.equal(vulns.vulnerabilities.length, start, 'all vulns remained');
  });
});
