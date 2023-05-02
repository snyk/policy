import { expect, test } from 'vitest';
import { create } from '../../lib';

test('add errors without options', async () => {
  let policy = await create();
  expect(policy.addPatch).toThrow(/^policy.add: required option/);
});

test('add errors without type', async () => {
  let policy = await create();
  expect(policy.add).toThrow(/^policy.add: unknown type/);
});

test('add errors without options 2', async () => {
  let policy = await create();

  expect(() => {
    const d1 = new Date();
    const d2 = new Date('2016-05-24T13:46:19.066Z');
    policy.addPatch({
      id: 'a',
      path: 'a > b',
      expires: d1,
    });

    policy.addPatch({
      id: 'a',
      path: 'a > b > c',
      expires: d2,
    });

    expect(Object.keys(policy.patch)).toBe(['a']);
    expect(policy.patch.a).toHaveLength(2);
    expect(policy.patch.a[1]['a > b > c'].expires).toBe(d2);
  });
});

test('add ignore with valid reasonType', async () => {
  let policy = await create();

  expect(() => {
    policy.addIgnore({
      id: 'a',
      path: 'a > b',
      reasonType: 'wont-fix',
    });

    expect(policy.ignore.a[0]['a > b'].reasonType).toBe('wont-fix');
  }).does.not.throw();
});

test('add ignore with invalid reasonType', async () => {
  let policy = await create();

  expect(() =>
    policy
      .addIgnore({
        id: 'a',
        path: 'a > b',
        reasonType: 'test',
      })
      .catch((err) => {
        expect(err.message).toBe('invalid reasonType test');
        throw err;
      })
  ).toThrow();
});

test('add ignore with valid ignoredBy', async () => {
  const ignoredBy = {
    name: 'Joe Bloggs',
    email: 'joe@acme.org',
  };

  let policy = await create();

  await policy.addIgnore({
    id: 'a',
    path: 'a > b',
    ignoredBy: ignoredBy,
  });

  expect(policy.ignore.a[0]['a > b'].ignoredBy).toBe(ignoredBy);
});

test('add ignore with invalid ignoredBy', async () => {
  const ignoredBy = {
    name: 'Joe Bloggs',
    email: 'joeacme.org',
  };

  let policy = await create();

  expect(() =>
    policy.addIgnore({
      id: 'a',
      path: 'a > b',
      ignoredBy: ignoredBy,
    })
  ).toThrow('ignoredBy.email must be a valid email address');
});
