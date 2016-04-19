var test = require('tap-only');
var policy = require('../../');
var fixtures = __dirname + '/../fixtures';
var dir1 = fixtures + '/ignore';
var dir2 = fixtures + '/ignore-duped';

test('multiple policies merge when the vuln id is the same in ignore', function (t) {
  return policy.load(['.', dir1, dir2], { loose: true }).then(function (res) {
    t.equal(res.suggest['npm:hawk:20160119'].length, 2, 'hawk is ignored in two places');
  });
});
