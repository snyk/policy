var test = require('tap').test;
var Promise = require('es6-promise').Promise; // jshint ignore:line
var fixtures = __dirname + '/../fixtures';
var vulns = require(fixtures + '/patch/vulns.json');
var policy = require('../../');

test('notes are attached', function (t) {
  return policy.load([fixtures + '/patch', fixtures + '/deep-policy']).then(function (policy) {
    policy.skipVerifyPatch = true;
    var res = policy.filter(vulns);
    t.ok(policy.suggest, 'has suggestions');
    var items = res.vulnerabilities.map(function (e) { return e.note; }).filter(Boolean);

    t.equal(items.length, 1, 'one has a note');

    t.match(items[0], new RegExp(vulns.name), 'found package name');
    t.notMatch(items[0], new RegExp('undefined'), 'undefined does not appear');
  });
});
