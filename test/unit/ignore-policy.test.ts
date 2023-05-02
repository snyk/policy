import { expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';

test('single load', async () => {
  const res = await policy.load(fixtures + '/ignore', {
    'ignore-policy': true,
  });

  expect(Object.keys(res.ignore)).toHaveLength(0);
  expect(Object.keys(res.patch)).toHaveLength(0);
  expect(res.filter).toBeTypeOf('function');
});

test('multiple load', async () => {
  const res = await policy.load([
    fixtures + '/patch',
    fixtures + '/patch-mean',
  ]);

  expect(Object.keys(res.ignore)).toHaveLength(0);
  expect(Object.keys(res.patch)).not.toHaveLength(0);
  expect(res.filter).toBeTypeOf('function');
});
