var test = require('tap-only');
var proxyquire = require('proxyquire');
var fixtures = __dirname + '/../fixtures';
var Promise = require('es6-promise').Promise; // jshint ignore:line
var path = require('path');
var sinon = require('sinon');
var writeSpy = sinon.spy();
var fs = require('then-fs');
var policy = proxyquire('../..', {
  'then-fs': {
    writeFile: function (filename, body) {
      writeSpy(filename, body);
      return Promise.resolve();
    }
  }
});

test.only('policy.save', function (t) {
  var filename = path.resolve(fixtures + '/ignore/.snyk');
  var asText = '';
  return fs.readFile(filename, 'utf8')
    .then(function (res) {
      asText = res;
      return res;
    })
    .then(policy.loadFromText)
    .then(function (res) {
      return policy.save(res, path.dirname(filename));
    })
    .then(function () {
      t.equal(writeSpy.callCount, 1, 'write only once');
      t.equal(writeSpy.args[0][0], filename, 'filename correct');
      t.equal(writeSpy.args[0][1].indexOf(asText), 0, 'body contains original');
    });
});