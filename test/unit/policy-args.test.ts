import { afterEach, expect, test, vi } from 'vitest';

import * as policy from '../../lib';
import { stripFunctions } from './helpers';

const fixtures = __dirname + '/../fixtures';

afterEach(() => {
  vi.resetAllMocks();
});

test('policy.load (no args)', async () => {
  vi.spyOn(process, 'cwd').mockReturnValue(fixtures + '/simple');

  const res = await policy.load();
  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
    __filename: '.snyk',
    __modified: res.__modified ? new Date(res.__modified) : false,
    __created: res.__created ? new Date(res.__created) : false,
  };

  expect(stripFunctions(res)).toStrictEqual(expected);
});

test('policy.load (options first)', async () => {
  vi.spyOn(process, 'cwd').mockReturnValue(fixtures + '/simple');

  const res = await policy.load({});
  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
    __filename: '.snyk',
    __modified: res.__modified ? new Date(res.__modified) : false,
    __created: res.__created ? new Date(res.__created) : false,
  };

  expect(stripFunctions(res)).toStrictEqual(expected);
});

test('policy loads without args - non simple', async () => {
  vi.spyOn(process, 'cwd').mockReturnValue(fixtures + '/ignore');

  const res = await policy.load();
  expect(Object.keys(res.ignore)).not.toBe(0);
});
