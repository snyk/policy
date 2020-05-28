const test = require('tap-only');
const policy = require('../..');
const path = require('path');
const fixtures = __dirname + '/../fixtures';

process.chdir(fixtures + '/simple');

test('policy.load (no args)', function (t) {
  return policy.load().then(function (res) {
    const expect = {
      version: 'v1.0.0',
      ignore: {},
      patch: {},
      __filename: path.relative(process.cwd(), fixtures + '/simple/.snyk'),
      __modified: res.__modified ? new Date(res.__modified) : false,
      __created: res.__created ? new Date(res.__created) : false,
    };

    t.deepEqual(stripFunctions(res), expect, 'policy is as expected');
  });
});

test('policy.load (options first)', function (t) {
  return policy.load({}).then(function (res) {
    const expect = {
      version: 'v1.0.0',
      ignore: {},
      patch: {},
      __filename: path.relative(process.cwd(), fixtures + '/simple/.snyk'),
      __modified: res.__modified ? new Date(res.__modified) : false,
      __created: res.__created ? new Date(res.__created) : false,
    };

    t.deepEqual(stripFunctions(res), expect, 'policy is as expected');
  });
});

test('policy loads without args - non simple', function (t) {
  process.chdir(fixtures + '/ignore');
  return policy.load().then(function (policy) {
    t.notEqual(Object.keys(policy.ignore), 0, 'has ignore rules');
  });
});

function stripFunctions(res) {
  // strip functions (as they don't land in the final config)
  Object.keys(res).map(function (key) {
    if (typeof res[key] === 'function') {
      delete res[key];
    }
  });

  return res;
}
