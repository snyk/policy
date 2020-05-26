const test = require('tap-only');
const policy = require('../../');
const fixtures = __dirname + '/../fixtures/issues/SC-1106/';
const withoutDash = fixtures + '/missing-dash.snyk';
const withDash = fixtures + '/with-dash.snyk';

test('missing dash on policy is fixed up', function (t) {
  const p1 = policy.load(withoutDash);
  const p2 = policy.load(withDash);

  const key = 'npm:hawk:20160119';

  return Promise.all([p1, p2]).then(function (res) {
    const paths1 = getPaths(res[0].ignore[key]);
    const paths2 = getPaths(res[1].ignore[key]);

    t.equal(paths1.length, 3, 'has 3 paths');
    t.equal(paths1.length, paths2.length, 'has equal length');
    t.deepEqual(paths1, paths2, 'missing dash was hotfixed');
  });
});

function getPaths(rules) {
  return rules
    .map(function (rule) {
      const keys = Object.keys(rule);
      if (keys.length === 1) {
        return keys.shift();
      }

      return false;
    })
    .filter(Boolean)
    .sort();
}
