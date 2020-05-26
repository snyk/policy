const policy = require('../../lib');
const test = require('tap').test;

test('test sensibly bails if gets an old .snyk format', function (t) {
  return policy
    .load(__dirname + '/../fixtures/old-snyk-config/')
    .then(function () {
      return true;
    })
    .then(function (res) {
      t.fail('was expecting an error, got ' + JSON.stringify(res));
    })
    .catch(function (e) {
      t.equal(e.message, 'old, unsupported .snyk format detected');
      t.equal(e.code, 'OLD_DOTFILE_FORMAT');
    });
});
