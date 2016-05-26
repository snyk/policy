var tap = require('tap');
var test = require('tap-only');
var policy = require('../../');
var fixtures = __dirname + '/../fixtures';
var dir = fixtures + '/severity-control';
var fs = require('fs');
var vulns = {};

tap.beforeEach(function (done) {
  // only contains medium + low - this file is read using fs to ensure refresh
  vulns = JSON.parse(fs.readFileSync(dir + '/vulns.json', 'utf8'));
  done();
});

test('severity-control: high (ok=false)', function (t) {
  return policy.loadFromText('failThreshold: high').then(function (res) {
    vulns = res.filter(vulns);
    t.equal(vulns.ok, false, 'we have 1 high vuln');
    t.notEqual(vulns.vulnerabilities.length, 0, 'vulns still available to read');
  });
});

test('severity-control: medium (ok=false)', function (t) {
  return policy.loadFromText('failThreshold: medium').then(function (res) {
    vulns = res.filter(vulns);
    t.equal(vulns.ok, false, 'only failing on medium severity');
    t.notEqual(vulns.vulnerabilities.length, 0, 'vulns still available to read');
  });
});

test('severity-control: low (ok=false)', function (t) {
  return policy.loadFromText('failThreshold: low').then(function (res) {
    vulns = res.filter(vulns);
    t.equal(vulns.ok, false, 'only failing on low severity');
    t.notEqual(vulns.vulnerabilities.length, 0, 'vulns still available to read');
  });
});

test('severity-control fails on bad value', function (t) {
  return policy.loadFromText('failThreshold: foo').then(function () {
    t.fail('should have thrown');
  }).catch(function (error) {
    t.equal(error.code, 'POLICY_BAD_THRESHOLD', 'failed correctly');
  });
});

test('severity-control ignores filtered vulns', function (t) {
  return policy.loadFromText(fs.readFileSync(dir + '/.snyk')).then(function (policy) {
    var res = policy.filter(vulns);
    t.equal(res.ok, true, 'low vulns ignored and high filtered out');
    var stripped = policy.stripFiltered(res);
    t.equal(stripped.vulnerabilities.length, 2, 'high vuln stripped and two left');
  });
});
