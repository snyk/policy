import { expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';

test('load different types of policies', () => {
  const dirs = [
    'patch',
    'deep-policy',
    'ignore',
    'ignore-duped',
    'ignore-expired',
    'issues/SC-1106/missing-dash.snyk',
    'issues/SC-1106/pre-update.snyk',
    'issues/SC-1106/with-dash.snyk',
    'patch-mean',
    'issues/BST-264/missing-path-to-package.snyk',
    'project.snyk',
    'project.snyk/project1',
    'project.snyk/project1.snyk',
  ];

  return Promise.all(
    dirs.map((dir) => {
      expect(() => policy.load(fixtures + '/' + dir, { loose: true })).not
        .toThrow;
    })
  );
});
