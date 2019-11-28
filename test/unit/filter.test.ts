import { test } from 'tap';
import * as policy from '../../';

const fixtures = __dirname + '/../fixtures/ignore';
const vulns = require(fixtures + '/vulns.json');

test('ignored vulns do not turn up in tests', function(t) {
  return policy.load(fixtures).then(function(config) {
    t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');

    // should strip all
    const result = config.filter(vulns);
    t.equal(result.ok, true, 'post filter, we have no vulns');
    t.deepEqual(result.vulnerabilities, [], 'vulns stripped');
  });
});
