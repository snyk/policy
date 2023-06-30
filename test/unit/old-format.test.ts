import { expect, test } from 'vitest';
import * as policy from '../../lib';

test('test sensibly bails if gets an old .snyk format', async () => {
  const oldSnykFormatError: NodeJS.ErrnoException = new Error('old, unsupported .snyk format detected');
  oldSnykFormatError.code = 'OLD_DOTFILE_FORMAT';

  await expect(() => policy.load(__dirname + '/../fixtures/old-snyk-config/')).rejects.toThrow(oldSnykFormatError);
});
