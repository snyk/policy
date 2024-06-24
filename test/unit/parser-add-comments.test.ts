import * as yaml from 'js-yaml';
import { expect, test } from 'vitest';
import addComments from '../../lib/parser/add-comments';

test('policy with no patches or ignores', () => {
  const res = addComments(
    yaml.dump({
      version: 'v1.0.0',
      patch: {},
      ignore: {},
    }),
  );

  expect(res).toMatch(/^# Snyk \(https:\/\/snyk\.io\) policy file/);
  expect(res).not.toMatch(
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
  );
  expect(res).not.toMatch(
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
  );
});

test('policy with patches', () => {
  const res = addComments(
    yaml.dump({
      version: 'v1.0.0',
      patch: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
      ignore: {},
    }),
  );

  expect(res).toMatch(
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
  );
  expect(res).not.toMatch(
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
  );
});

test('policy with ignores', () => {
  const res = addComments(
    yaml.dump({
      version: 'v1.0.0',
      patch: {},
      ignore: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
    }),
  );

  expect(res).toMatch(
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
  );
  expect(res).not.toMatch(
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
  );
});

test('policy with ignores and patches', () => {
  const res = addComments(
    yaml.dump({
      version: 'v1.0.0',
      patch: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
      ignore: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
    }),
  );

  expect(res).toMatch(
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
  );
  expect(res).toMatch(
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
  );
});
