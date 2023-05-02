import { expect, test } from 'vitest';
import * as policy from '../../lib';

test('broken patch should not be in output', async () => {
  const res = await policy.load(
    __dirname + '/../fixtures/issues/BST-264/missing-path-to-package.snyk',
    { loose: true }
  );

  expect(res.patch).toStrictEqual({});
});
