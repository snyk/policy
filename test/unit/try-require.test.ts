import * as path from 'path';
import { afterEach, beforeEach, expect, test } from 'vitest';

import { cache, tryRequire } from '../../lib/try-require';

const fixtures = path.resolve(__dirname, '..', 'fixtures', 'try-require');

const fixture = (name: string) => path.resolve(fixtures, name, 'package.json');

beforeEach(() => {
  cache.reset();
});

afterEach(() => {
  cache.reset();
});

test('parses a package.json and enriches it', async () => {
  const pkg = await tryRequire(fixture('with-name'));

  expect(pkg).toBeTruthy();
  expect(pkg!.name).toBe('with-name');
  expect(pkg!.version).toBe('1.2.3');
  expect(pkg!.dependencies).toEqual({ lodash: '^4.0.0' });
  expect(pkg!.devDependencies).toEqual({ vitest: '^1.0.0' });
  expect(pkg!.__filename).toBe(fixture('with-name'));
});

test('defaults missing dependencies/devDependencies to empty objects', async () => {
  const pkg = await tryRequire(fixture('no-name'));

  expect(pkg!.dependencies).toEqual({});
  expect(pkg!.devDependencies).toEqual({});
});

test('falls back to the directory name when name is missing', async () => {
  const pkg = await tryRequire(fixture('no-name'));

  expect(pkg!.name).toBe('no-name');
});

test('returns null on malformed JSON', async () => {
  const pkg = await tryRequire(fixture('malformed'));

  expect(pkg).toBeNull();
});

test('returns null when the file does not exist', async () => {
  const pkg = await tryRequire(fixture('does-not-exist'));

  expect(pkg).toBeNull();
});

test('strips a leading UTF BOM before parsing', async () => {
  const pkg = await tryRequire(fixture('bom'));

  expect(pkg).toBeTruthy();
  expect(pkg!.name).toBe('bom');
  // The BOM is preserved in the recorded leading whitespace.
  expect((pkg as any).leading).toBe('﻿');
});

test('sets snyk to the directory when a .snyk file is present', async () => {
  const filename = fixture('with-snyk');
  const pkg = await tryRequire(filename);

  expect((pkg as any).snyk).toBe(path.dirname(filename));
});

test('does not set snyk when no .snyk file is present', async () => {
  const pkg = await tryRequire(fixture('with-name'));

  expect((pkg as any).snyk).toBe(false);
});

test('sets shrinkwrap when npm-shrinkwrap.json is present', async () => {
  const pkg = await tryRequire(fixture('with-shrinkwrap'));

  expect(pkg!.shrinkwrap).toBe(true);
});

test('does not set shrinkwrap when npm-shrinkwrap.json is absent', async () => {
  const pkg = await tryRequire(fixture('with-name'));

  expect(pkg!.shrinkwrap).toBeUndefined();
});

test('returns a deep clone on a cache hit, not the cached reference', async () => {
  const filename = fixture('with-name');

  const first = await tryRequire(filename);
  const second = await tryRequire(filename);

  // Same data...
  expect(second).toEqual(first);
  // ...but distinct object graphs, so mutating one does not affect the other.
  expect(second).not.toBe(first);
  expect(second!.dependencies).not.toBe(first!.dependencies);

  (second as any).dependencies.lodash = 'mutated';
  const third = await tryRequire(filename);
  expect(third?.dependencies?.lodash).toBe('^4.0.0');
});

test('populates the cache after a successful read', async () => {
  const filename = fixture('with-name');
  expect(cache.get(filename)).toBeUndefined();

  await tryRequire(filename);

  expect(cache.get(filename)).toBeTruthy();
});
