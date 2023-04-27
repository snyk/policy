import { promises as fs } from 'fs';
import * as path from 'path';
import { afterEach, test } from 'tap';
import sinon from 'sinon';
import * as policy from '../../lib';

const fixtures = __dirname + '/../fixtures';

var sandbox = sinon.createSandbox();

afterEach(function () {
  sandbox.restore();
});

test('policy.save', function (t) {
  const writeFileStub = sandbox
    .stub(fs, 'writeFile')
    .returns(Promise.resolve());

  const filename = path.resolve(fixtures + '/ignore/.snyk');
  let asText = '';
  return fs
    .readFile(filename, 'utf8')
    .then(function (res) {
      asText = res.trim();
      return asText;
    })
    .then(policy.loadFromText)
    .then(function (res) {
      return policy.save(res, path.dirname(filename));
    })
    .then(function () {
      t.equal(writeFileStub.callCount, 1, 'write only once');
      t.equal(writeFileStub.args[0][0], filename, 'filename correct');
      const parsed = writeFileStub.args[0][1].trim();
      t.equal(parsed, asText, 'body contains original');
      t.match(
        parsed,
        '# Snyk (https://snyk.io) policy file, patches or ' +
          'ignores known vulnerabilities.',
        'body contains comments'
      );
    });
});
