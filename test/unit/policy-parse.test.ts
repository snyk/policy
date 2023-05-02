import { expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures/issues/SC-1106/';
const withoutDash = fixtures + '/missing-dash.snyk';
const withDash = fixtures + '/with-dash.snyk';

test('missing dash on policy is fixed up', () => {
  const p1 = policy.load(withoutDash);
  const p2 = policy.load(withDash);

  const key = 'npm:hawk:20160119';

  return Promise.all([p1, p2]).then((res) => {
    const paths1 = getPaths(res[0].ignore[key]);
    const paths2 = getPaths(res[1].ignore[key]);

    expect(paths1).toHaveLength(3);
    expect(paths1).toHaveLength(paths2.length);
    expect(paths1).toStrictEqual(paths2);
  });
});

function getPaths(rules) {
  return rules
    .map((rule) => {
      const keys = Object.keys(rule);
      if (keys.length === 1) {
        return keys.shift();
      }

      return false;
    })
    .filter(Boolean)
    .sort();
}
