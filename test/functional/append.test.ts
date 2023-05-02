import { expect, test } from 'vitest';
import * as policy from '../../lib';
import { needsFixing } from '../../lib/parser/v1';

const fixtures = __dirname + '/../fixtures/issues/SC-1106/';
const withDash = fixtures + '/pre-update.snyk';

test('merging new policy data does not corrupt', async () => {
  const res = await policy.load(withDash);
  res.addIgnore({
    id: 'npm:hawk:20160119',
    path: 'octonode > request > hawk',
    expires: new Date('2016-05-24T13:46:19.066Z'),
    reason: 'none given',
  });

  expect(needsFixing(res.ignore)).toBe(false);
  expect(Object.keys(res.ignore['npm:hawk:20160119'])).toHaveLength(3);
});
