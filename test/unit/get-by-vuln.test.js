var test = require('tap-only');
var fixtures = __dirname + '/../fixtures';
var fs = require('then-fs');
var getByVuln = require('../../lib/match').getByVuln;
var loadFromText = require('../../').loadFromText;
var policy = require(fixtures + '/ignore/parsed.json');
var vulns = require(fixtures + '/ignore/vulns.json');

test('getByVuln (no args)', function (t) {
  var res = getByVuln();
  t.equal(res, null, 'no args means null');
  t.end();
});

test('getByVuln (no vulns)', function (t) {
  var res = getByVuln(policy);
  t.equal(res, null, 'no args means null');
  t.end();
});

test('getByVuln', function (t) {
  var res = vulns.vulnerabilities.map(getByVuln.bind(null, policy));
  res.forEach(function (res, i) {
    t.equals(res.type, 'ignore', 'expect ignore for ' + res.id);
    t.equals(res.id, vulns.vulnerabilities[i].id, 'matched id: ' + res.id);
  });
  t.end();
});

test('getByVuln with star rules', function (t) {
  var id = 'npm:hawk:20160119';
  var vuln = vulns.vulnerabilities.filter(function (v) {
    return v.id === id;
  }).pop();

  return fs.readFile(fixtures + '/star-rule.txt', 'utf8').then(loadFromText).then(function (policy) {
    var res = getByVuln(policy, vuln);
    t.equal(res.id, id, 'found the vuln');
    t.ok(res.rule.length > 0, 'rule has length');
    t.ok(true);
  });
});

test('getByVuln with exact match rules', function (t) {
  var id = 'npm:hawk:20160119';
  var vuln = vulns.vulnerabilities.filter(function (v) {
    return v.id === id;
  }).pop();

  return fs.readFile(fixtures + '/exact-rule.txt', 'utf8').then(loadFromText).then(function (policy) {
    var res = getByVuln(policy, vuln);
    t.equal(res.id, id, 'found the vuln');
    t.ok(res.rule.length > 0, 'rule has length');
    t.ok(true);
  });
});
