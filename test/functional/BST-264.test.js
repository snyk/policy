const test = require('tap-only');
const policy = require('../../');

test('broken patch should not be in output', function (t) {
  return policy
    .load(
      __dirname + '/../fixtures/issues/BST-264/missing-path-to-package.snyk',
      { loose: true }
    )
    .then(function (policy) {
      t.deepEqual(policy.patch, {}, 'patch section is empty');
    });
});
