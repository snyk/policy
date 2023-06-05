import { promises as fs } from 'fs';
import { expect, test } from 'vitest';
import { getByVuln, loadFromText } from '../../lib';
import { expectTypeOf } from 'vitest';
import { VulnRule } from 'lib/types';

const fixtures = __dirname + '/../fixtures';
const policy = require(fixtures + '/ignore/parsed.json');
const vulns = require(fixtures + '/ignore/vulns.json');

test('getByVuln (no args)', () => {
  const res = getByVuln();
  expect(res).toBeNull();
});

test('getByVuln (no vulns)', () => {
  const res = getByVuln(policy);
  expect(res).toBeNull();
});

test('getByVuln', () => {
  const res = vulns.vulnerabilities.map(getByVuln.bind(null, policy));
  res.forEach((res, i) => {
    expect(res.type).toBe('ignore');
    expect(res.id).toBe(vulns.vulnerabilities[i].id);
  });
});

test('getByVuln with star rules', async () => {
  const id = 'npm:hawk:20160119';
  const vuln = vulns.vulnerabilities
    .filter((v) => {
      return v.id === id;
    })
    .pop();

  const file = await fs.readFile(fixtures + '/star-rule.txt', 'utf8');
  const policy = await loadFromText(file);
  const res = getByVuln(policy, vuln);

  expect(res).not.toBeNull();

  if (res !== null) {
    expect(res.id).toBe(id);
    expect(res.rule).not.empty;
  }
});

test('getByVuln with exact match rules', async () => {
  const id = 'npm:hawk:20160119';
  const vuln = vulns.vulnerabilities.filter((v) => v.id === id).pop();

  const file = await fs.readFile(fixtures + '/exact-rule.txt', 'utf8');
  const policy = await loadFromText(file);
  const res = getByVuln(policy, vuln);

  expect(res).not.toBeNull();

  if (res !== null) {
    expect(res.id).toBe(id);
    expect(res.rule).not.empty;
  }
});
