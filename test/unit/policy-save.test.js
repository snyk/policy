const test = require('tap-only');
const proxyquire = require('proxyquire');
const fixtures = __dirname + '/../fixtures';
const path = require('path');
const sinon = require('sinon');
const writeSpy = sinon.spy();
const fs = require('promise-fs');
const policy = proxyquire('../..', {
  'promise-fs': {
    writeFile: function (filename, body) {
      writeSpy(filename, body);
      return Promise.resolve();
    },
  },
});

test('policy.save', function (t) {
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
      t.equal(writeSpy.callCount, 1, 'write only once');
      t.equal(writeSpy.args[0][0], filename, 'filename correct');
      const parsed = writeSpy.args[0][1].trim();
      t.equal(parsed, asText, 'body contains original');
      t.match(
        parsed,
        '# Snyk (https://snyk.io) policy file, patches or ' +
          'ignores known vulnerabilities.',
        'body contains comments'
      );
    });
});
