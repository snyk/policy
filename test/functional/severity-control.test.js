const tap = require('tap');
const test = require('tap-only');
const policy = require('../../');
const fixtures = __dirname + '/../fixtures';
const dir = fixtures + '/severity-control';
const fs = require('fs');
let vulns = {};

tap.beforeEach(function (done) {
  // only contains medium + low - this file is read using fs to ensure refresh
  vulns = JSON.parse(fs.readFileSync(dir + '/vulns.json', 'utf8'));
  done();
});

test('severity-control: high (ok=true)', function (t) {
  return policy.loadFromText('failThreshold: high').then(function (res) {
    vulns = res.filter(vulns);
    t.equal(vulns.ok, true, 'only failing on high severity');
    t.notEqual(
      vulns.vulnerabilities.length,
      0,
      'vulns still available to read'
    );
  });
});

test('severity-control: medium (ok=false)', function (t) {
  return policy.loadFromText('failThreshold: medium').then(function (res) {
    vulns = res.filter(vulns);
    t.equal(vulns.ok, false, 'only failing on medium severity');
    t.notEqual(
      vulns.vulnerabilities.length,
      0,
      'vulns still available to read'
    );
  });
});

test('severity-control: low (ok=false)', function (t) {
  return policy.loadFromText('failThreshold: low').then(function (res) {
    vulns = res.filter(vulns);
    t.equal(vulns.ok, false, 'only failing on low severity');
    t.notEqual(
      vulns.vulnerabilities.length,
      0,
      'vulns still available to read'
    );
  });
});

test('severity-control fails on bad value', function (t) {
  return policy
    .loadFromText('failThreshold: foo')
    .then(function () {
      t.fail('should have thrown');
    })
    .catch(function (error) {
      t.equal(error.code, 'POLICY_BAD_THRESHOLD', 'failed correctly');
    });
});
