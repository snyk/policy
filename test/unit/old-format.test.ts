import { expect, test } from 'vitest';
import * as policy from '../../lib';

test('test sensibly bails if gets an old .snyk format', () => {
  expect(() =>
    policy.load(__dirname + '/../fixtures/old-snyk-config/').catch((e) => {
      expect(e.message).toBe('old, unsupported .snyk format detected');
      expect(e.code).toBe('OLD_DOTFILE_FORMAT');
      throw e;
    })
  ).rejects.toThrow();
});
