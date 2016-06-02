var test = require('tap-only');
var Promise = require('es6-promise').Promise; // jshint ignore:line
var policy = require('../../');
var fixtures = __dirname + '/../fixtures/versions/v';

test('versions', function (t) {
  return Promise.all([1,2].map(function (v) {
    t.test('v' + v, function (t) {
      return policy.load(fixtures + v + '.snyk').then(function (policy) {
        return t.ok(policy.toString().indexOf('v' + v) !== -1);
      });
    });
  }));
});
