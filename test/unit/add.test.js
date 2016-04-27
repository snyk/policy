var test = require('tap').test;
var create = require('../../lib').create;

test('add errors without options', function (t) {
  return create().then(function (policy) {
    t.throws(function () {
      policy.addPatch();
    }, /^policy.add: required option/, 'errors without opts');
  });
});

test('add errors without type', function (t) {
  return create().then(function (policy) {
    t.throws(function () {
      policy.add();
    }, /^policy.add: unknown type/, 'errors without type');
  });
});

test('add errors without options', function (t) {
  return create().then(function (policy) {
    var d1 = new Date();
    var d2 = new Date('2016-05-24T13:46:19.066Z');
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

