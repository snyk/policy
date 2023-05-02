import { promises as fs } from 'fs';
import * as path from 'path';
import { afterEach, expect, test, vi } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';

afterEach(() => {
  vi.resetAllMocks();
});

test('policy.save', async () => {
  const mockLatestVersion = 'v1.2.3';

  const writeFileStub = vi.spyOn(fs, 'writeFile').mockResolvedValueOnce();
  vi.spyOn(policy, 'latestVersion').mockReturnValue(mockLatestVersion);

  const filename = path.resolve(fixtures + '/ignore/.snyk');
  let asText = '';

  const file = await fs.readFile(filename, 'utf8');
  asText = file.trim();

  const res = await policy.loadFromText(asText);

  await policy.save(res, path.dirname(filename));

  expect(writeFileStub).toHaveBeenCalledOnce();
  expect(writeFileStub).toHaveBeenCalledWith(filename, expect.anything());

  // always save with the latest schema version
  asText = asText.replace('version: v1.0.0', 'version: ' + mockLatestVersion);

  const parsed = (writeFileStub.mock.calls[0][1] as string).trim();
  expect(parsed).toBe(asText);
  expect(parsed).toMatch(
    '# Snyk (https://snyk.io) policy file, patches or ' +
      'ignores known vulnerabilities.'
  );
});
