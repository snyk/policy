var test = require('tap-only');
var policy = require('../../');
var fixtures = __dirname + '/../fixtures';
var dir1 = fixtures + '/empty';
var dir2 = fixtures + '/patch';

test('multiple directories, one with policy, one without', function (t) {
  return policy.load([dir1, dir2], { loose: true }).then(function (res) {
    t.ok(res.patch, 'patch property is present');
    t.equal(Object.keys(res.patch).length, 3, 'patches found');
  });
});
