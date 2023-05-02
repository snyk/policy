import fs from 'fs';
import { beforeEach, expect, test } from 'vitest';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';
const dir = fixtures + '/severity-control';
let vulns: any = {};

beforeEach(() => {
  // only contains medium + low - this file is read using fs to ensure refresh
  vulns = JSON.parse(fs.readFileSync(dir + '/vulns.json', 'utf8'));
});

test('severity-control: high (ok=true)', async () => {
  const res = await policy.loadFromText('failThreshold: high');
  vulns = res.filter(vulns);

  expect(vulns.ok).toBe(true);
  expect(vulns.vulnerabilities).not.toHaveLength(0);
});

test('severity-control: medium (ok=false)', async () => {
  const res = await policy.loadFromText('failThreshold: medium');
  vulns = res.filter(vulns);

  expect(vulns.ok).toBe(false);
  expect(vulns.vulnerabilities).not.toHaveLength(0);
});

test('severity-control: low (ok=false)', async () => {
  const res = await policy.loadFromText('failThreshold: low');
  vulns = res.filter(vulns);

  expect(vulns.ok).toBe(false);
  expect(vulns.vulnerabilities.length).not.toBe(0);
});

test('severity-control fails on bad value', () => {
  expect(() =>
    policy.loadFromText('failThreshold: foo').catch((error) => {
      expect(error.code).toBe('POLICY_BAD_THRESHOLD');
      throw error;
    })
  ).rejects.toThrow();
});
