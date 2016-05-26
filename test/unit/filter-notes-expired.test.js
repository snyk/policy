var test = require('tap-only');
var Promise = require('es6-promise').Promise; // jshint ignore:line
var fixtures = __dirname + '/../fixtures';
var vulns = require(fixtures + '/patch/vulns.json');

var policy = require('../../');
var notes = require('../../lib/filter/notes');

test('expired vulns do not have notes', function (t) {
  return policy.load([fixtures + '/patch', fixtures + '/deep-policy']).then(function (policy) {
    var key = Object.keys(policy.suggest['npm:semver:20150403'][0]).pop();

    // tweak the expiry to force code path
    policy.suggest['npm:semver:20150403'][0][key].expires = (new Date(-1)).toJSON();

    var res = notes(
      policy.suggest,
      vulns.vulnerabilities,
      fixtures
    );

    var items = res.map(function (e) { return e.note; }).filter(Boolean);

    t.equal(items.length, 0, 'no notes found');
  });
});
