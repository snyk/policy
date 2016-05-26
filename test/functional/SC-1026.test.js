var test = require('tap-only');
var policy = require('../../');
var fixtures = __dirname + '/../fixtures';
var dir = fixtures + '/filter-and-track';
var vulns = require(dir + '/vulns.json');

test('filtered vulns can still be reviewed', function (t) {
  return policy.load(dir, { loose: true }).then(function (policy) {
    policy.skipVerifyPatch = true;
    var res = policy.filter(vulns);
    t.equal(res.ok, false, 'still vulnerable');

    var ignored = res.vulnerabilities.filter(function (vuln) {
      if (vuln.filtered) {
        return vuln.filtered.type === 'ignore';
      }
    }).shift();

    t.equal(ignored.id, 'npm:hawk:20160119', 'correct single vuln ignored');
    t.equal(ignored.filtered.metadata.reason, 'hawk got bumped', 'has reason');

    var patched = res.vulnerabilities.filter(function (vuln) {
      if (vuln.filtered) {
        return vuln.filtered.type === 'patch';
      }
    }).shift();

    t.equal(patched.id, 'npm:tar:20151103', 'correct single vuln patched');
  });
});
