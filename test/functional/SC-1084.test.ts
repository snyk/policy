import { expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';
const dir1 = fixtures + '/ignore';
const dir2 = fixtures + '/ignore-duped';

test('multiple policies merge when the vuln id is the same in ignore', async () => {
  const res = await policy.load(['.', dir1, dir2], { loose: true });

  expect(res.suggest['npm:hawk:20160119']).toHaveLength(2);
});
