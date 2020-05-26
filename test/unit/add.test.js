const test = require('tap').test;
const create = require('../../lib').create;

test('add errors without options', function (t) {
  return create().then(function (policy) {
    t.throws(
      function () {
        policy.addPatch();
      },
      /^policy.add: required option/,
      'errors without opts'
    );
  });
});

test('add errors without type', function (t) {
  return create().then(function (policy) {
    t.throws(
      function () {
        policy.add();
      },
      /^policy.add: unknown type/,
      'errors without type'
    );
  });
});

test('add errors without options', function (t) {
  return create().then(function (policy) {
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

    t.deepEqual(Object.keys(policy.patch), ['a'], '`a` is the only root');
    t.deepEqual(policy.patch.a.length, 2, 'two paths on `a`');
    t.deepEqual(policy.patch.a[1]['a > b > c'].expires, d2, 'metadata saved');
  });
});

test('add ignore with valid reasonType', function (t) {
  return create()
    .then(function (policy) {
      return policy.addIgnore({
        id: 'a',
        path: 'a > b',
        reasonType: 'wont-fix',
      });
    })
    .then(function (policy) {
      t.ok('error not thrown');
      t.deepEqual(
        policy.ignore.a[0]['a > b'].reasonType,
        'wont-fix',
        'metadata saved'
      );
    })
    .catch(function () {
      t.fail('error thrown thrown');
    });
});

test('add ignore with invalid reasonType', function (t) {
  return create()
    .then(function (policy) {
      return policy.addIgnore({
        id: 'a',
        path: 'a > b',
        reasonType: 'test',
      });
    })
    .then(function () {
      t.fail('error not thrown');
    })
    .catch(function (err) {
      t.equal(err.message, 'invalid reasonType test', 'error is thrown');
    });
});

test('add ignore with valid ignoredBy', function (t) {
  const ignoredBy = {
    name: 'Joe Bloggs',
    email: 'joe@acme.org',
  };
  return create()
    .then(function (policy) {
      return policy.addIgnore({
        id: 'a',
        path: 'a > b',
        ignoredBy: ignoredBy,
      });
    })
    .then(function (policy) {
      t.ok('error not thrown');
      t.deepEqual(
        policy.ignore.a[0]['a > b'].ignoredBy,
        ignoredBy,
        'metadata saved'
      );
    })
    .catch(function () {
      t.fail('error thrown thrown');
    });
});

test('add ignore with invalid ignoredBy', function (t) {
  const ignoredBy = {
    name: 'Joe Bloggs',
    email: 'joeacme.org',
  };
  return create()
    .then(function (policy) {
      return policy.addIgnore({
        id: 'a',
        path: 'a > b',
        ignoredBy: ignoredBy,
      });
    })
    .then(function () {
      t.fail('error not thrown');
    })
    .catch(function (err) {
      t.equal(
        err.message,
        'ignoredBy.email must be a valid email address',
        'error is thrown'
      );
    });
});
