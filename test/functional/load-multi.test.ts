import { expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';
const dir1 = fixtures + '/empty';
const dir2 = fixtures + '/patch';

test('multiple directories, one with policy, one without', async () => {
  const res = await policy.load([dir1, dir2], { loose: true });

  expect(res.patch).toBeTruthy();
  expect(Object.keys(res.patch)).toHaveLength(3);
});
