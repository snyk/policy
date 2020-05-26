const test = require('tap-only');
const policy = require('../../');
const fixtures = __dirname + '/../fixtures/issues/SC-1106/';
const withDash = fixtures + '/pre-update.snyk';
const needsFixing = require('../../lib/parser/v1').needsFixing;

test('merging new policy data does not corrupt', function (t) {
  return policy.load(withDash).then(function (policy) {
    policy.addIgnore({
      id: 'npm:hawk:20160119',
      path: 'octonode > request > hawk',
      expires: new Date('2016-05-24T13:46:19.066Z'),
      reason: 'none given',
    });

    t.equal(needsFixing(policy.ignore), false, 'no corruption');
    t.equal(
      Object.keys(policy.ignore['npm:hawk:20160119']).length,
      3,
      'has 3 rules'
    );
  });
});
