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
    t.isa(res.filtered.ignore, Array);
    t.ok(res.filtered.ignore.length > 0, 'some vulns ignored');
    t.isa(res.filtered.patch, Array);
    t.notEqual(res.filtered.patch.length, 0, 'some vulns ignored due to patch');
  });
});
