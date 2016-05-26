var test = require('tap-only');
var policy = require('../../');
var fixtures = __dirname + '/../fixtures';
var dir = fixtures + '/filter-and-track';
var vulns = require(dir + '/vulns.json');

test('filtered vulns can still be reviewed', function (t) {
  t.plan(7);

  policy.load(dir, { loose: true }).then(function (policy) {
    policy.skipVerifyPatch = true;
    var res = policy.filter(vulns);
    t.equal(res.ok, true, 'vulns ignored/patched via policy');

    var ignored = res.vulnerabilities.filter(function (vuln) {
      if (vuln.filtered) {
        return vuln.filtered.type === 'ignore';
      }
    }).map(function (vuln) {
      return {
        id: vuln.id,
        filtered: vuln.filtered,
      };
    });

    t.equal(ignored.length, 2, 'two ignored vulns');
    var ids = [
      'npm:hawk:20160119',
      'npm:is-my-json-valid:20160118',
    ];

    ignored.forEach(function (vuln) {
      t.notEqual(ids.indexOf(vuln.id), -1, 'expected id');
      t.ok(vuln.filtered.metadata.reason, 'has reason');
    });

    var patched = res.vulnerabilities.filter(function (vuln) {
      if (vuln.filtered) {
        return vuln.filtered.type === 'patch';
      }
    }).shift();

    t.equal(patched.id, 'npm:tar:20151103', 'correct single vuln patched');
  });
});
