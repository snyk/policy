import { expect, test } from 'vitest';

import { isObject } from 'lib/types';

test('isObject', () => {
  // Testing for objects
  expect(isObject({})).toBe(true);
  expect(isObject({ a: 1 })).toBe(true);

  // Testing for non-objects
  expect(isObject(null)).toBe(false);
  expect(isObject([])).toBe(false);
  expect(isObject(42)).toBe(false);
  expect(isObject('a string')).toBe(false);
  expect(isObject(true)).toBe(false);
  expect(isObject(undefined)).toBe(false);
});
