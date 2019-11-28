import * as test from 'tap-only';
import * as policy from '../../';
const fixtures = __dirname + '/../fixtures';
const dir1 = fixtures + '/empty';
const dir2 = fixtures + '/patch';

test('multiple directories, one with policy, one without', function(t) {
  return policy.load([dir1, dir2], { loose: true }).then(function(res) {
    t.ok(res.patch, 'patch property is present');
    t.equal(Object.keys(res.patch).length, 3, 'patches found');
  });
});
