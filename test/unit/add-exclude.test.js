const test = require('tap').test;
const create = require('../../lib').create;

test('use of invalid file pattern-group throws errors', function (t) {
  return create().then(function (policy) {
    t.throws(
      function () {
        const invalidGroup = 'unmanaged';
        policy.addExclude('./deps/*.ts', invalidGroup);
      },
      'invalid file pattern-group'
    );
  });
});

test('add a new file pattern to default group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(
      function () {
        policy.addExclude('./deps/*.ts');

        const expected = { 'global': ['./deps/*.ts'] };

        t.deepEqual( policy.exclude, expected, 'pattern added');
      },
    );
  });
});

test('add a new file pattern to global-group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(
      function () {
        const validGroup = 'global';
        policy.addExclude('./deps/*.ts', validGroup);

        const expected = { 'global': ['./deps/*.ts'] };

        t.deepEqual( policy.exclude, expected, 'pattern added');
      },
    );
  });
});

test('add a new file pattern to code-group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(
      function () {
        const validGroup = 'code';
        policy.addExclude('./deps/*.ts', validGroup);

        const expected = { 'code': ['./deps/*.ts'] };

        t.deepEqual( policy.exclude, expected, 'pattern added');
      },
    );
  });
});

test('add two new unique file pattern to a group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(
      function () {
        policy.addExclude('./deps/*.ts');
        policy.addExclude('./vendor/*.ts');
        const expected = { 'global': ['./deps/*.ts', './vendor/*.ts'] };

        t.deepEqual(policy.exclude, expected, 'pattern added');
      },
    );
  });
});

test('ignore already existing patterns', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(
      function () {
        policy.addExclude('./deps/*.ts');
        policy.addExclude('./deps/*.ts');
        policy.addExclude('./vendor/*.ts');
        policy.addExclude('./deps/*.ts');

        const expected = { 'global': ['./deps/*.ts', './vendor/*.ts'] };

        t.deepEqual(policy.exclude, expected, 'pattern added');
      },
    );
  });
});
