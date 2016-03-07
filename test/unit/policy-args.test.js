var test = require('tap-only');
var policy = require('../..');
var path = require('path');
var fixtures = __dirname + '/../fixtures';

process.chdir(fixtures + '/simple');

test('policy.load (no args)', function (t) {
  return policy.load().then(function (res) {
    var expect = {
      version: 'v1',
      ignore: {},
      patch: {},
      __filename: path.relative(process.cwd(), fixtures + '/simple/.snyk'),
      __modified: res.__modified ? new Date(res.__modified) : false,
      __created: res.__created ? new Date(res.__created) : false
    };

    t.deepEqual(res, expect, 'policy is as expected');
  });
});

test('policy.load (options first)', function (t) {
  return policy.load({}).then(function (res) {
    var expect = {
      version: 'v1',
      ignore: {},
      patch: {},
      __filename: path.relative(process.cwd(), fixtures + '/simple/.snyk'),
      __modified: res.__modified ? new Date(res.__modified) : false,
      __created: res.__created ? new Date(res.__created) : false
    };

    t.deepEqual(res, expect, 'policy is as expected');
  });
});

