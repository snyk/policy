import test from 'tap-only';

const fixtures = __dirname + '/../fixtures';
const vulns = require(fixtures + '/patch/vulns.json');

// mock the vulns
vulns.vulnerabilities.forEach(function (v) {
  // v.from.unshift('ignore@1.0.0');
});

import * as policy from '../../lib';
import notes from '../../lib/filter/notes';

test('ignored vulns do not turn up in tests', function (t) {
  return policy
    .load([fixtures + '/patch', fixtures + '/deep-policy'])
    .then(function (res) {
      const start = vulns.vulnerabilities.length;
      t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');
      t.ok(res.suggest, 'has suggestions');

      // FIXME patch vulns doesn't match anything in the ignore/.snyk
      vulns.vulnerabilities = notes(res.suggest, vulns.vulnerabilities);

      t.equal(
        start,
        vulns.vulnerabilities.length,
        'post filter nothing changed'
      );
      const items = vulns.vulnerabilities
        .map(function (e) {
          return e.note;
        })
        .filter(Boolean);

      t.equal(items.length, 1, 'one has a note');

      t.match(items[0], new RegExp(vulns.name), 'found package name');
      t.notMatch(
        items[0],
        new RegExp('undefined'),
        'undefined does not appear'
      );
    });
});
