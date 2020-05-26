const test = require('tap-only');
const addComments = require('../../lib/parser/add-comments');
const yaml = require('js-yaml');

test('policy with no patches or ignores', function (t) {
  const res = addComments(
    yaml.safeDump({
      version: 'v1.0.0',
      patch: {},
      ignore: {},
    })
  );

  t.ok(
    res.match(/^# Snyk \(https:\/\/snyk\.io\) policy file/),
    'addComments adds initial comment'
  );
  t.notMatch(
    res,
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
    'addComments does not add patch comment'
  );
  t.notMatch(
    res,
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
    'addComments does not add ignore comment'
  );
  t.end();
});

test('policy with patches', function (t) {
  const res = addComments(
    yaml.safeDump({
      version: 'v1.0.0',
      patch: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
      ignore: {},
    })
  );

  t.match(
    res,
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
    'addComments adds patch comment'
  );
  t.notMatch(
    res,
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
    'addComments does not add ignore comment'
  );
  t.end();
});

test('policy with ignores', function (t) {
  const res = addComments(
    yaml.safeDump({
      version: 'v1.0.0',
      patch: {},
      ignore: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
    })
  );

  t.match(
    res,
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
    'addComments adds ignore comment'
  );
  t.notMatch(
    res,
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
    'addComments does not add patch comment'
  );
  t.end();
});

test('policy with ignores and patches', function (t) {
  const res = addComments(
    yaml.safeDump({
      version: 'v1.0.0',
      patch: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
      ignore: {
        'glue > hapi > joi > moment': [
          {
            patched: '2016-02-26T16:19:06.050Z',
          },
        ],
      },
    })
  );

  t.match(
    res,
    '# ignores vulnerabilities until expiry date; change ' +
      'duration by modifying expiry date\nignore:',
    'addComments adds ignore comment'
  );
  t.match(
    res,
    '# patches apply the minimum changes required to fix ' +
      'a vulnerability\npatch:',
    'addComments adds patch comment'
  );
  t.end();
});
