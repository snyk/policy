import test from 'tap-only';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';

test('single load', function (t) {
  return policy
    .load(fixtures + '/ignore', { 'ignore-policy': true })
    .then(function (res) {
      t.equal(Object.keys(res.ignore).length, 0, 'ignore policy is empty');
      t.equal(Object.keys(res.patch).length, 0, 'patch policy is empty');
      t.type(res.filter, 'function', 'helper methods attached');
    });
});

test('multiple load', function (t) {
  return policy
    .load([fixtures + '/patch', fixtures + '/patch-mean'])
    .then(function (res) {
      t.equal(Object.keys(res.ignore).length, 0, 'ignore policy is empty');
      t.not(Object.keys(res.patch).length, 0, 'patch policy is not empty');
      t.type(res.filter, 'function', 'helper methods attached');
    });
});
