const test = require('tap').test;
const create = require('../../lib').create;

test('use of invalid file pattern-group throws errors', function (t) {
  return create().then(function (policy) {
    t.throws(function () {
      const invalidGroup = 'unmanaged';
      policy.addExclude('./deps/*.ts', invalidGroup);
    }, 'invalid file pattern-group');
  });
});

test('add a new file pattern to default group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      policy.addExclude('./deps/*.ts');

      const expected = { global: ['./deps/*.ts'] };

      t.deepEqual(policy.exclude, expected, 'pattern added');
    });
  });
});

test('add a new file pattern to global-group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      const validGroup = 'global';
      policy.addExclude('./deps/*.ts', validGroup);

      const expected = { global: ['./deps/*.ts'] };

      t.deepEqual(policy.exclude, expected, 'pattern added');
    });
  });
});

test('add a new file pattern to code-group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      const validGroup = 'code';
      policy.addExclude('./deps/*.ts', validGroup);

      const expected = { code: ['./deps/*.ts'] };

      t.deepEqual(policy.exclude, expected, 'pattern added');
    });
  });
});

test('add a new file pattern to iac drift-group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      const validGroup = 'iac-drift';

      policy.addExclude('!aws_iam_*', validGroup);
      policy.addExclude('aws_s3_bucket.*', validGroup);

      const expected = {
        [validGroup]: ['!aws_iam_*', 'aws_s3_bucket.*'],
      };

      t.deepEqual(policy.exclude, expected, 'pattern added to iac-drift');
    });
  });
});

test('add two new unique file pattern to a group', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      policy.addExclude('./deps/*.ts');
      policy.addExclude('./vendor/*.ts');
      const expected = { global: ['./deps/*.ts', './vendor/*.ts'] };

      t.deepEqual(policy.exclude, expected, 'pattern added');
    });
  });
});

test('replace duplicates patterns', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      policy.addExclude('./deps/*.ts');
      policy.addExclude('./deps/*.ts');
      policy.addExclude('./vendor/*.ts');
      policy.addExclude('./deps/*.ts');

      const expected = { global: ['./vendor/*.ts', './deps/*.ts'] };

      t.deepEqual(policy.exclude, expected, 'pattern added');
    });
  });
});

test('add dates and reasons', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      policy.addExclude('./deps/*.ts', 'global', {
        expires: '2092-12-24',
        reason: 'incidents already fixed by user',
      });

      t.deepEqual(
        policy.exclude['global'][0]['./deps/*.ts'].expires,
        '2092-12-24',
        'expires added with the correct format'
      );
      t.deepEqual(
        policy.exclude['global'][0]['./deps/*.ts'].reason,
        'incidents already fixed by user',
        'reason added with the correct format'
      );
    });
  });
});

test('replace existing objects', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      policy.addExclude('./deps/*.ts', 'global', {
        expires: '2092-12-24',
        reason: 'incidents already fixed by user',
      });

      policy.addExclude('./deps/*.ts', 'global', {
        expires: '2192-12-24',
        reason: 'it will never happen',
      });

      t.deepEqual(
        policy.exclude['global'][0]['./deps/*.ts'].expires,
        '2192-12-24',
        'expire replaced'
      );
      t.deepEqual(
        policy.exclude['global'][0]['./deps/*.ts'].reason,
        'it will never happen',
        'reason replaced'
      );
    });
  });
});

test('only replace duplicates', function (t) {
  return create().then(function (policy) {
    t.doesNotThrow(function () {
      policy.addExclude('./deps/*.ts', 'global', {
        expires: '2092-12-24',
        reason: 'incidents already fixed by user',
      });

      policy.addExclude('./vendor/*.go', 'global');

      policy.addExclude('./deps/*.ts', 'global', {
        expires: '2192-12-24',
        reason: 'it will never happen',
      });

      t.deepEqual(
        policy.exclude['global'][0],
        './vendor/*.go',
        'should keep unique pattern'
      );

      t.deepEqual(
        policy.exclude['global'][1]['./deps/*.ts'].expires,
        '2192-12-24',
        'expire replaced'
      );
      t.deepEqual(
        policy.exclude['global'][1]['./deps/*.ts'].reason,
        'it will never happen',
        'reason replaced'
      );
    });
  });
});
