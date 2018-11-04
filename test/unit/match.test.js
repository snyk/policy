var test = require('tap-only');
var fs = require('fs');
var fixtures = __dirname + '/../fixtures';
var vulns = JSON.parse(fs.readFileSync(fixtures + '/jsbin.json', 'utf8')).vulnerabilities;
var vuln = vulns.filter(function (v) {
  return v.id === 'npm:uglify-js:20150824';
}).pop();
var vulnWithGitUrl = JSON.parse(fs.readFileSync(fixtures + '/patch-with-git-url.json', 'utf8'));
var policy = require('../../');

test('match logic', function (t) {
  var rule = {
    'express-hbs > handlebars > uglify-js': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z'
    },
    'handlebars > uglify-js': {
      reason: 'done this already',
      expires: '2016-03-01T19:53:46.310Z'
    }
  };

  var pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('match (triggering not found)', function (t) {
  var vuln = require(fixtures + '/path-not-found.json');
  var rule = {
    'glue > hapi > joi > moment': {
      'patched': '2016-02-26T16:19:06.050Z'
    }
  };

  var pathMatch = policy.matchToRule(vuln, rule);
  t.equal(pathMatch, false, 'path does not match');
  t.end();
});

test('star match', function (t) {
  var rule = {
    '*': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z'
    }
  };

  var pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('mixed star match', function (t) {
  var rule = {
    '* > uglify-js': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z'
    }
  };

  var pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('match star at end', function (t) {
  var rule = {
    'handlebars@2.0.0 > *': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z'
    }
  };

  var pathMatch = policy.matchToRule(vuln, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('rule with git url as dependency', function (t) {
  var rule = {
    'patchable-vuln > qs': {
      patched: '2018-11-04T12:47:13.696Z',
    },
  };

  var pathMatch = policy.matchToRule(vulnWithGitUrl, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('no match', function (t) {
  var rule = {
    '* > moment': {
      reason: 'None given',
      expires: '2016-03-01T19:49:50.633Z'
    }
  };

  var pathMatch = policy.matchToRule(vuln, rule);
  t.notOk(pathMatch, 'correctly does not match');
  t.end();
});
