const test = require('tap-only');
const policy = require('../..');
const demunge = require('../../lib/parser').demunge;
const path = require('path');
const fs = require('promise-fs');
const fixtures = __dirname + '/../fixtures';

test('module loads', function (t) {
  t.isa(policy, 'object', 'policy has loaded an object');
  t.end();
});

test('policy.load (single)', function (t) {
  return policy.load(fixtures + '/simple').then(function (res) {
    const expect = {
      version: 'v1.0.0',
      ignore: {},
      patch: {},
      __filename: path.relative(process.cwd(), fixtures + '/simple/.snyk'),
      __modified: res.__modified ? new Date(res.__modified) : false,
      __created: res.__created ? new Date(res.__created) : false,
    };

    stripFunctions(res);

    t.deepEqual(res, expect, 'policy is as expected');
  });
});

test('policy.load (single .snyk in path name)', function (t) {
  return policy.load(fixtures + '/project.snyk').then(function (res) {
    const expect = {
      version: 'v1.0.0',
      ignore: {},
      patch: {},
      __filename: path.relative(
        process.cwd(),
        fixtures + '/project.snyk/.snyk'
      ),
      __modified: res.__modified ? new Date(res.__modified) : false,
      __created: res.__created ? new Date(res.__created) : false,
    };

    stripFunctions(res);

    t.deepEqual(res, expect, 'policy is as expected');
  });
});

test('policy.load (double .snyk in path name)', function (t) {
  return policy
    .load(fixtures + '/project.snyk/project1.snyk')
    .then(function (res) {
      const expect = {
        version: 'v1.0.0',
        ignore: {},
        patch: {},
        __filename: path.relative(
          process.cwd(),
          fixtures + '/project.snyk/project1.snyk/.snyk'
        ),
        __modified: res.__modified ? new Date(res.__modified) : false,
        __created: res.__created ? new Date(res.__created) : false,
      };

      stripFunctions(res);

      t.deepEqual(res, expect, 'policy is as expected');
    });
});

test('policy.load (single .snyk in path name but at upper level)', function (t) {
  return policy.load(fixtures + '/project.snyk/project1').then(function (res) {
    const expect = {
      version: 'v1.0.0',
      ignore: {},
      patch: {},
      __filename: path.relative(
        process.cwd(),
        fixtures + '/project.snyk/project1/.snyk'
      ),
      __modified: res.__modified ? new Date(res.__modified) : false,
      __created: res.__created ? new Date(res.__created) : false,
    };

    stripFunctions(res);

    t.deepEqual(res, expect, 'policy is as expected');
  });
});

test('policy.load (multiple - ignore first)', function (t) {
  return policy
    .load([fixtures + '/ignore', fixtures + '/patch'])
    .then(function (res) {
      const filename = path.relative(process.cwd(), fixtures + '/ignore/.snyk');
      t.equal(res.__filename, filename, 'first file is __filename');

      const patchPkg = require(fixtures + '/patch/package.json');

      const patchIds = Object.keys(res.patch);
      const id = patchIds.shift();

      const deepPatchPath = Object.keys(res.patch[id][0]).shift().split(' > ');

      // FIXME is this right, should it include the version?
      t.equal(
        deepPatchPath[0],
        patchPkg.name + '@' + patchPkg.version,
        'first policy was prepended'
      );
    });
});

test('policy.load (multiple - ignore last)', function (t) {
  return policy
    .load([fixtures + '/patch', fixtures + '/ignore'])
    .then(function (res) {
      const ids = [
        'npm:hawk:20160119',
        'npm:is-my-json-valid:20160118',
        'npm:tar:20151103',
        'npm:method-override:20170927',
        'npm:marked:20170907',
      ];
      t.deepEqual(res.ignore, {}, 'nothing is ignored');
      t.ok(res.suggest, 'suggestions are present');
      t.deepEqual(
        Object.keys(res.suggest),
        ids,
        'suggestions are present and correct'
      );
    });
});

test('policy.load (multiple - ignore last - trust deep policy)', function (t) {
  return policy
    .load([fixtures + '/patch', fixtures + '/ignore'], {
      'trust-policies': true,
    })
    .then(function (res) {
      const ids = [
        'npm:hawk:20160119',
        'npm:is-my-json-valid:20160118',
        'npm:tar:20151103',
        'npm:method-override:20170927',
        'npm:marked:20170907',
      ];
      t.notOk(res.suggest, 'no suggestions');
      t.notEqual(Object.keys(res.ignore).length, 0, 'has more than one ignore');
      t.deepEqual(
        Object.keys(res.ignore),
        ids,
        'inherited ignores are correct'
      );
    });
});

test('policy.load (merge)', function (t) {
  const id = 'npm:uglify-js:20151024';
  return policy
    .load([fixtures + '/patch', fixtures + '/patch-mean'])
    .then(function (res) {
      t.equal(res.patch[id].length, 3, 'expect 2 from mean, 1 from patch');

      const formatted = demunge(res);

      const single = formatted.patch
        .filter(function (p) {
          return p.id === id;
        })
        .shift();

      t.equal(single.paths.length, 3, 'still have 3 paths for single patch');

      const filtered = single.paths.filter(function (item) {
        return item.path.indexOf('mean') === 0;
      });

      t.equal(filtered.length, 2, 'two of which come from mean');
    });
});

test('policy.loadFromText', function (t) {
  return fs
    .readFile(fixtures + '/ignore/.snyk', 'utf8')
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
  return policy
    .load([fixtures + '/patch', fixtures + '/404'], { loose: true })
    .then(function (res) {
      const ids = [
        'npm:uglify-js:20150824',
        'npm:uglify-js:20151024',
        'npm:semver:20150403',
      ];
      t.deepEqual(Object.keys(res.patch), ids, 'policy loaded');
    });
});

test('policy.load (multiple - expect ENOENT)', function (t) {
  return policy
    .load([fixtures + '/patch', fixtures + '/404'], { loose: false })
    .then(function () {
      t.fail('missing policy should have thrown');
    })
    .catch(function (e) {
      t.equal(e.code, 'ENOENT', 'errors correctly');
    });
});

function stripFunctions(res) {
  // strip functions (as they don't land in the final config)
  Object.keys(res).map(function (key) {
    if (typeof res[key] === 'function') {
      delete res[key];
    }
  });
}
