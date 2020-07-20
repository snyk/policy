const test = require('tap-only');
const fixtures = __dirname + '/../fixtures';
const fs = require('promise-fs');
const getByVuln = require('../../lib/match').getByVuln;
const loadFromText = require('../../').loadFromText;
const policy = require(fixtures + '/ignore/parsed.json');
const vulns = require(fixtures + '/ignore/vulns.json');

test('getByVuln (no args)', function (t) {
  const res = getByVuln();
  t.equal(res, null, 'no args means null');
  t.end();
});

test('getByVuln (no vulns)', function (t) {
  const res = getByVuln(policy);
  t.equal(res, null, 'no args means null');
  t.end();
});

test('getByVuln', function (t) {
  const res = vulns.vulnerabilities.map(getByVuln.bind(null, policy));
  res.forEach(function (res, i) {
    t.equals(res.type, 'ignore', 'expect ignore for ' + res.id);
    t.equals(res.id, vulns.vulnerabilities[i].id, 'matched id: ' + res.id);
  });
  t.end();
});

test('getByVuln with star rules', function (t) {
  const id = 'npm:hawk:20160119';
  const vuln = vulns.vulnerabilities
    .filter(function (v) {
      return v.id === id;
    })
    .pop();

  return fs
    .readFile(fixtures + '/star-rule.txt', 'utf8')
    .then(loadFromText)
    .then(function (policy) {
      const res = getByVuln(policy, vuln);
      t.equal(res.id, id, 'found the vuln');
      t.ok(res.rule.length > 0, 'rule has length');
      t.ok(true);
    });
});

test('getByVuln with exact match rules', function (t) {
  const id = 'npm:hawk:20160119';
  const vuln = vulns.vulnerabilities
    .filter(function (v) {
      return v.id === id;
    })
    .pop();

  return fs
    .readFile(fixtures + '/exact-rule.txt', 'utf8')
    .then(loadFromText)
    .then(function (policy) {
      const res = getByVuln(policy, vuln);
      t.equal(res.id, id, 'found the vuln');
      t.ok(res.rule.length > 0, 'rule has length');
      t.ok(true);
    });
});
