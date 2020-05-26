const test = require('tap-only');
const policy = require('../..');
const fixtures = __dirname + '/../fixtures';

test('single load', function (t) {
  return policy
    .load(fixtures + '/ignore', { 'ignore-policy': true })
    .then(function (res) {
      t.equal(Object.keys(res.ignore).length, 0, 'ignore policy is empty');
      t.equal(Object.keys(res.patch).length, 0, 'patch policy is empty');
      t.isa(res.filter, 'function', 'helper methods attached');
    });
});

test('multiple load', function (t) {
  return policy
    .load([fixtures + '/patch', fixtures + '/patch-mean'])
    .then(function (res) {
      t.equal(Object.keys(res.ignore).length, 0, 'ignore policy is empty');
      t.notEqual(Object.keys(res.patch).length, 0, 'patch policy is not empty');
      t.isa(res.filter, 'function', 'helper methods attached');
    });
});
