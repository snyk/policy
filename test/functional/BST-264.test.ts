import test from 'tap-only';
import * as policy from '../../lib';

test('broken patch should not be in output', function (t) {
  return policy
    .load(
      __dirname + '/../fixtures/issues/BST-264/missing-path-to-package.snyk',
      { loose: true }
    )
    .then(function (policy) {
      t.same(policy.patch, {}, 'patch section is empty');
    });
});
