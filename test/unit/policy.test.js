var test = require('tap-only');
var policy = require('../..');
var path = require('path');
var fs = require('then-fs');
var fixtures = __dirname + '/../fixtures';

test('module loads', function (t) {
  t.isa(policy, 'object', 'policy has loaded an object');
  t.end();
});

test('policy.load (single)', function (t) {
  return policy.load(fixtures + '/simple').then(function (res) {
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

test('policy.load (multiple - ignore first)', function (t) {
  return policy.load([fixtures + '/ignore', fixtures + '/patch']).then(function (res) {
    var filename = path.relative(process.cwd(), fixtures + '/ignore/.snyk');
    t.equal(res.__filename, filename, 'first file is __filename');

    var patchPkg = require(fixtures + '/patch/package.json');

    var patchIds = Object.keys(res.patch);
    var id = patchIds.shift();

    var deepPatchPath = Object.keys(res.patch[id][0]).shift().split(' > ');

    // FIXME is this right, should it include the version?
    t.equal(deepPatchPath[0], patchPkg.name + '@' + patchPkg.version, 'first policy was prepended');
  });
});

test('policy.load (multiple - ignore last)', function (t) {
  return policy.load([fixtures + '/patch', fixtures + '/ignore']).then(function (res) {
    var ids = [
      'npm:hawk:20160119',
      'npm:is-my-json-valid:20160118',
      'npm:tar:20151103',
    ];
    t.deepEqual(res.ignore, {}, 'nothing is ignored');
    t.ok(res.suggest, 'suggestions are present');
    t.deepEqual(Object.keys(res.suggest), ids, 'suggestions are present and correct');
  });
});

test('policy.load (multiple - ignore last - trust deep policy)', function (t) {
  return policy.load([fixtures + '/patch', fixtures + '/ignore'], { 'trust-policies': true }).then(function (res) {
    var ids = [
      'npm:hawk:20160119',
      'npm:is-my-json-valid:20160118',
      'npm:tar:20151103',
    ];
    t.notOk(res.suggest, 'no suggestions');
    t.notEqual(Object.keys(res.ignore).length, 0, 'has more than one ignore');
    t.deepEqual(Object.keys(res.ignore), ids, 'inherited ignores are correct');
  });
});

test('policy.load (ignore option)', function (t) {
  return policy.load(fixtures + '/ignore', { 'ignore-policy': true }).then(function (res) {
    t.deepEqual(res, {}, 'ignore policy is empty');
  });
});

test('policy.loadFromText', function (t) {
  return fs.readFile(fixtures + '/ignore/.snyk', 'utf8')
    .then(policy.loadFromText)
    .then(function (fromText) {

      return policy.load(fixtures + '/ignore').then(function (fromDir) {
        t.deepEqual(fromText.patch, fromDir.patch);
        t.deepEqual(fromText.ignore, fromDir.ignore);
        t.equal(fromText.version, fromDir.version);
      });
    });
});

test('policy.load (multiple - ENOENT - loose)', function (t) {
  return policy.load([fixtures + '/patch', fixtures + '/404'], { loose: true }).then(function (res) {
    var ids = [
      'npm:uglify-js:20150824',
      'npm:uglify-js:20151024',
    ];
    t.deepEqual(Object.keys(res.patch), ids, 'policy loaded');
  });
});

test('policy.load (multiple - expect ENOENT)', function (t) {
  return policy.load([fixtures + '/patch', fixtures + '/404'], { loose: false }).then(function () {
      t.fail('missing policy should have thrown');
  }).catch(function (e) {
    t.equal(e.code, 'ENOENT', 'errors correctly');
  });
});
// save: save,
// getByVuln: match.getByVuln,
// matchToRule: match.matchToRule,