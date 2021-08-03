const test = require('tap-only');
const fs = require('fs');
const fixtures = __dirname + '/../fixtures';
const vulns = JSON.parse(
  fs.readFileSync(fixtures + '/jsbin.json', 'utf8')
).vulnerabilities;
const vuln = vulns
  .filter(function (v) {
    return v.id === 'npm:uglify-js:20150824';
  })
  .pop();
const vulnWithGitUrl = JSON.parse(
  fs.readFileSync(fixtures + '/patch-with-git-url.json', 'utf8')
);
const exactMatchVuln = {
  from: ['a-dir/a-file.json', 'foo', 'bar'],
};
const policy = require('../../');

test('match logic', function (t) {
  const rule = {
    'express-hbs > handlebars > uglify-js': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z',
    },
    'handlebars > uglify-js': {
      reason: 'done this already',
      expires: '2016-03-01T19:53:46.310Z',
    },
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('match (triggering not found)', function (t) {
  const vuln = require(fixtures + '/path-not-found.json');
  const rule = {
    'glue > hapi > joi > moment': {
      patched: '2016-02-26T16:19:06.050Z',
    },
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  t.equal(pathMatch, false, 'path does not match');
  t.end();
});

test('star match', function (t) {
  const rule = {
    '*': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z',
    },
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('mixed star match', function (t) {
  const rule = {
    '* > uglify-js': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z',
    },
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('match star at end', function (t) {
  const rule = {
    'handlebars@2.0.0 > *': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z',
    },
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('rule with git url as dependency', function (t) {
  const rule = {
    'patchable-vuln > qs': {
      patched: '2018-11-04T12:47:13.696Z',
    },
  };

  const pathMatch = policy.matchToRule(vulnWithGitUrl, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('no match', function (t) {
  const rule = {
    '* > moment': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z',
    },
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  t.notOk(pathMatch, 'correctly does not match');
  t.end();
});

test('exact match  does not match when path arrays are not equal', function (t) {
  const rule = {
    'a-dir/a-file.json': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.notOk(pathMatch, 'does not match when path arrays are not equal');
  t.end();
});

test('exact match  matches when path arrays are equal', function (t) {
  const rule = {
    'a-dir/a-file.json > foo > bar': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('exact match  matches when rule is *', function (t) {
  const rule = {
    '*': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('exact match  matches when path matches before *', function (t) {
  const rule = {
    'a-dir/a-file.json > *': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('exact match  does not match when path does not match before *', function (t) {
  const rule = {
    'a-dir/a-file.json > wrong > *': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.notOk(pathMatch, 'correctly does not match');
  t.end();
});
