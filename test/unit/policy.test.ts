import { promises as fs } from 'fs';
import * as path from 'path';
import { expect, test } from 'vitest';

import * as policy from '../../lib';
import { stripFunctions } from './helpers';

const fixtures = __dirname + '/../fixtures';

test('module loads', () => {
  expect(policy).toBeTypeOf('object');
});

test('policy.load (single)', async () => {
  const res = await policy.load(fixtures + '/simple');
  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
    __filename: path.relative(process.cwd(), fixtures + '/simple/.snyk'),
    __modified: res.__modified ? new Date(res.__modified) : false,
    __created: res.__created ? new Date(res.__created) : false,
  };

  stripFunctions(res);

  expect(res).toStrictEqual(expected);
});

test('policy.load (single .snyk in path name)', async () => {
  const res = await policy.load(fixtures + '/project.snyk');

  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
    __filename: path.relative(process.cwd(), fixtures + '/project.snyk/.snyk'),
    __modified: res.__modified ? new Date(res.__modified) : false,
    __created: res.__created ? new Date(res.__created) : false,
  };

  stripFunctions(res);

  expect(res).toStrictEqual(expected);
});

test('policy.load (double .snyk in path name)', async () => {
  const res = await policy.load(fixtures + '/project.snyk/project1.snyk');

  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
    __filename: path.relative(
      process.cwd(),
      fixtures + '/project.snyk/project1.snyk/.snyk',
    ),
    __modified: res.__modified ? new Date(res.__modified) : false,
    __created: res.__created ? new Date(res.__created) : false,
  };

  stripFunctions(res);

  expect(res).toStrictEqual(expected);
});

test('policy.load (single .snyk in path name but at upper level)', async () => {
  const res = await policy.load(fixtures + '/project.snyk/project1');
  const expected = {
    version: 'v1.0.0',
    ignore: {},
    patch: {},
    __filename: path.relative(
      process.cwd(),
      fixtures + '/project.snyk/project1/.snyk',
    ),
    __modified: res.__modified ? new Date(res.__modified) : false,
    __created: res.__created ? new Date(res.__created) : false,
  };

  stripFunctions(res);

  expect(res).toStrictEqual(expected);
});

test('policy.load (multiple - ignore first)', async () => {
  const res = await policy.load([fixtures + '/ignore', fixtures + '/patch']);

  const filename = path.relative(process.cwd(), fixtures + '/ignore/.snyk');
  expect(res.__filename).toBe(filename);

  const patchPkg = require(fixtures + '/patch/package.json');

  const patchIds = Object.keys(res.patch);
  const id = patchIds.shift();

  expect(id).toBeDefined();
  if (id === undefined) {
    return;
  }

  const deepPatchPath = Object.keys(res.patch[id][0]).shift()!.split(' > ');

  // FIXME is this right, should it include the version?
  expect(deepPatchPath[0]).toBe(patchPkg.name + '@' + patchPkg.version);
});

test('policy.load (multiple - ignore last)', async () => {
  const res = await policy.load([fixtures + '/patch', fixtures + '/ignore']);

  const ids = [
    'npm:hawk:20160119',
    'npm:is-my-json-valid:20160118',
    'npm:tar:20151103',
    'npm:method-override:20170927',
    'npm:marked:20170907',
  ];

  expect(res.ignore).toStrictEqual({});
  expect(res.suggest).toBeTruthy();
  expect(Object.keys(res.suggest)).toStrictEqual(ids);
});

test('policy.load (multiple - ignore last - trust deep policy)', async () => {
  const res = await policy.load([fixtures + '/patch', fixtures + '/ignore'], {
    'trust-policies': true,
  });

  const ids = [
    'npm:hawk:20160119',
    'npm:is-my-json-valid:20160118',
    'npm:tar:20151103',
    'npm:method-override:20170927',
    'npm:marked:20170907',
  ];

  expect(res.suggest).toBeFalsy();
  expect(Object.keys(res.ignore)).not.toHaveLength(0);
  expect(Object.keys(res.ignore)).toStrictEqual(ids);
});

test('policy.load (merge)', async () => {
  const id = 'npm:uglify-js:20151024';
  const res = await policy.load([
    fixtures + '/patch',
    fixtures + '/patch-mean',
  ]);

  expect(res.patch[id]).toHaveLength(3);

  const formatted = policy.demunge(res);

  const single = formatted.patch.filter((p) => p.id === id).shift()!;

  expect(single).toBeDefined();

  if (single !== undefined) {
    expect(single.paths).toHaveLength(3);

    const filtered = single.paths.filter(
      (item) => item.path.indexOf('mean') === 0,
    );

    expect(filtered).toHaveLength(2);
  }
});

test('policy.loadFromText', async () => {
  const file = await fs.readFile(fixtures + '/ignore/.snyk', 'utf8');
  const fromText = await policy.loadFromText(file);

  const fromDir = await policy.load(fixtures + '/ignore');

  expect(fromText.patch).toStrictEqual(fromDir.patch);
  expect(fromText.ignore).toStrictEqual(fromDir.ignore);
  expect(fromText.version).toBe(fromDir.version);
});

test('policy.load (multiple - ENOENT - loose)', async () => {
  const res = await policy.load([fixtures + '/patch', fixtures + '/404'], {
    loose: true,
  });

  const ids = [
    'npm:uglify-js:20150824',
    'npm:uglify-js:20151024',
    'npm:semver:20150403',
  ];

  expect(Object.keys(res.patch)).toStrictEqual(ids);
});

test('policy.load (multiple - expect ENOENT)', () => {
  expect(
    policy
      .load([fixtures + '/patch', fixtures + '/404'], { loose: false })
      .catch((e) => {
        expect(e.code).toBe('ENOENT');
        throw e;
      }),
  ).rejects.toThrow();
});
