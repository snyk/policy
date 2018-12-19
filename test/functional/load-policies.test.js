var test = require('tap-only');
var policy = require('../../');
var fixtures = __dirname + '/../fixtures';

test('load different types of policies', function (t) {

  var dirs = [
    'patch',
    'deep-policy',
    'ignore',
    'ignore-duped',
    'ignore-expired',
    'issues/SC-1106/missing-dash.snyk',
    'issues/SC-1106/pre-update.snyk',
    'issues/SC-1106/with-dash.snyk',
    'patch-mean',
    'issues/BST-264/missing-path-to-package.snyk',
  ];

  return Promise.all(dirs.map(function (dir) {
    return policy.load(fixtures + '/' + dir, { loose: true }).then(function (res) {
      t.ok('load succeeded for ' + dir);
    });
  }));
});
