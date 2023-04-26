const test = require('tap-only');
const policy = require('../../');
const fixtures = __dirname + '/../fixtures';
const dir = fixtures + '/filter-and-track';
const vulns = require(dir + '/vulns.json');

test('filtered vulns can still be reviewed', function (t) {
  return policy.load(dir, { loose: true }).then(function (policy) {
    policy.skipVerifyPatch = true;
    const res = policy.filter(vulns);
    t.equal(res.ok, false, 'still vulnerable');
    t.type(res.filtered.ignore, Array);
    t.ok(res.filtered.ignore.length > 0, 'some vulns ignored');
    t.type(res.filtered.patch, Array);
    t.not(res.filtered.patch.length, 0, 'some vulns ignored due to patch');
  });
});
