import { expect, test } from 'vitest';

import * as policy from '../../lib';
import { Vulnerability } from 'lib/types';

const vulnReport = {
  ok: false,
  vulnerabilities: [
    {
      id: 'SNYK-CC-K8S-44',
      from: ['infrastructure/iac/testdata/RBAC-copy.yaml'],
    } as Vulnerability,
  ],
};

test('empty ignore ruleset does not error', async () => {
  const config = await policy.loadFromText(`ignore:`);

  const vulns = config.filter({ ...vulnReport });

  expect(vulns.ok).toBe(false);
});

test('empty ignore pathObj does not error', async () => {
  const config = await policy.loadFromText(
    `ignore:
      SNYK-CC-K8S-44:
    `,
  );

  const vulns = config.filter({ ...vulnReport });

  expect(vulns.ok).toBe(false);
});

test('empty ignore rule ignores matching vulnerability', async () => {
  const config = await policy.loadFromText(
    `ignore:
      SNYK-CC-K8S-44:
      - 'infrastructure/iac/testdata/RBAC-copy.yaml > [DocId: 1] > clusterrole > rules[0] > verbs':
    `,
  );

  const vulns = config.filter({ ...vulnReport });

  expect(vulns.ok).toBe(true);
});

test('empty patch ruleset does not error', async () => {
  const config = await policy.loadFromText(`ignore:`);

  const vulns = config.filter({ ...vulnReport });

  expect(vulns.ok).toBe(false);
});

test('empty patch pathObj does not error', async () => {
  const config = await policy.loadFromText(
    `patch:
      SNYK-CC-K8S-44:
    `,
  );

  const vulns = config.filter({ ...vulnReport });

  expect(vulns.ok).toBe(false);
});

test('empty patch rule does not error', async () => {
  const config = await policy.loadFromText(
    `patch:
      SNYK-CC-K8S-44:
      - 'infrastructure/iac/testdata/RBAC-copy.yaml > [DocId: 1] > clusterrole > rules[0] > verbs':
    `,
  );

  const vulns = config.filter({ ...vulnReport });

  expect(vulns.ok).toBe(false);
});
