import { expect, test } from 'vitest';

import { create } from '../../lib';
import { PatternGroup } from '../../lib/types';

test('use of invalid file pattern-group throws errors', async () => {
  let policy = await create();

  expect(() => {
    const invalidGroup = 'unmanaged' as PatternGroup;
    policy.addExclude('./deps/*.ts', invalidGroup);
  }).toThrow('invalid file pattern-group');
});

test('add a new file pattern to default group', async (t) => {
  let policy = await create();

  expect(() => {
    policy.addExclude('./deps/*.ts');

    const expected = { global: ['./deps/*.ts'] };
    expect(policy.exclude).toStrictEqual(expected);
  }).does.not.toThrow();
});

test('add a new file pattern to global-group', async (_t) => {
  let policy = await create();

  expect(() => {
    const validGroup = 'global';
    policy.addExclude('./deps/*.ts', validGroup);

    const expected = { global: ['./deps/*.ts'] };
    expect(policy.exclude).toStrictEqual(expected);
  }).does.not.toThrow();
});

test('add a new file pattern to code-group', async (_t) => {
  let policy = await create();
  expect(() => {
    const validGroup = 'code';
    policy.addExclude('./deps/*.ts', validGroup);

    const expected = { code: ['./deps/*.ts'] };
    expect(policy.exclude).toStrictEqual(expected);
  }).does.not.toThrow();
});

test('add a new file pattern to iac drift-group', async (_t) => {
  let policy = await create();
  expect(() => {
    const validGroup = 'iac-drift';

    policy.addExclude('!aws_iam_*', validGroup);
    policy.addExclude('aws_s3_bucket.*', validGroup);

    const expected = {
      [validGroup]: ['!aws_iam_*', 'aws_s3_bucket.*'],
    };

    expect(policy.exclude).toStrictEqual(expected);
  }).does.not.toThrow();
});

test('add two new unique file pattern to a group', async (_t) => {
  let policy = await create();
  expect(() => {
    policy.addExclude('./deps/*.ts');
    policy.addExclude('./vendor/*.ts');
    const expected = { global: ['./deps/*.ts', './vendor/*.ts'] };

    expect(policy.exclude).toStrictEqual(expected);
  }).does.not.toThrow();
});

test('replace duplicates patterns', async (_t) => {
  let policy = await create();

  expect(() => {
    policy.addExclude('./deps/*.ts');
    policy.addExclude('./deps/*.ts');
    policy.addExclude('./vendor/*.ts');
    policy.addExclude('./deps/*.ts');

    const expected = { global: ['./vendor/*.ts', './deps/*.ts'] };

    expect(policy.exclude).toStrictEqual(expected);
  }).does.not.toThrow();
});

test('add dates and reasons', async (t) => {
  let policy = await create();
  expect(() => {
    policy.addExclude('./deps/*.ts', 'global', {
      expires: '2092-12-24',
      reason: 'incidents already fixed by user',
    });

    const exclude1 = policy.exclude?.['global'][0];
    expect(exclude1).toBeDefined();
    expect(exclude1).not.toBeTypeOf('string');

    if (exclude1 && typeof exclude1 !== 'string') {
      expect(exclude1['./deps/*.ts'].expires).toBe('2092-12-24');
      expect(exclude1['./deps/*.ts'].reason).toBe(
        'incidents already fixed by user'
      );
    }
  }).does.not.toThrow();
});

test('replace existing objects', async (_t) => {
  let policy = await create();
  expect(() => {
    policy.addExclude('./deps/*.ts', 'global', {
      expires: '2092-12-24',
      reason: 'incidents already fixed by user',
    });

    policy.addExclude('./deps/*.ts', 'global', {
      expires: '2192-12-24',
      reason: 'it will never happen',
    });

    const exclude1 = policy.exclude?.['global'][0];
    expect(exclude1).toBeDefined();
    expect(exclude1).not.toBeTypeOf('string');

    if (exclude1 && typeof exclude1 !== 'string') {
      expect(exclude1['./deps/*.ts'].expires).toBe('2192-12-24');
      expect(exclude1['./deps/*.ts'].reason).toBe('it will never happen');
    }
  }).does.not.toThrow();
});

test('only replace duplicates', async (_t) => {
  let policy = await create();
  expect(() => {
    policy.addExclude('./deps/*.ts', 'global', {
      expires: '2092-12-24',
      reason: 'incidents already fixed by user',
    });

    policy.addExclude('./vendor/*.go', 'global');

    policy.addExclude('./deps/*.ts', 'global', {
      expires: '2192-12-24',
      reason: 'it will never happen',
    });

    expect(policy.exclude?.['global'][0]).toBe('./vendor/*.go');

    const exclude2 = policy.exclude?.['global'][1];
    expect(exclude2).toBeDefined();
    expect(exclude2).not.toBeTypeOf('string');

    if (exclude2 && typeof exclude2 !== 'string') {
      expect(exclude2['./deps/*.ts'].expires).toBe('2192-12-24');
      expect(exclude2['./deps/*.ts'].reason).toBe('it will never happen');
    }
  }).does.not.toThrow();
});
