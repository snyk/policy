const test = require('tap-only');
const fs = require('fs');
const fixtures = __dirname + '/../fixtures';

const vulnWithGitUrl = JSON.parse(
  fs.readFileSync(fixtures + '/patch-with-git-url.json', 'utf8')
);
const exactMatchVuln = {
  from: ['a-dir/a-file.json', 'foo', 'bar'],
};
const policy = require('../../');

test('matchToRule', function (t) {
  const vuln = {
    from: [
      'projectName', // this is ignored
      'jsbin@3.35.9',
      'handlebars@2.0.0',
      'uglify-js@2.3.6',
    ],
  };

  const tt = {
    'match exact path': {
      rule: {
        'jsbin@3.35.9 > handlebars@2.0.0 > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match without versions': {
      rule: {
        'jsbin > handlebars > uglify-js': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match mixed version and versionless': {
      rule: {
        'jsbin > handlebars@2.0.0 > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on only root dependency': {
      rule: {
        'jsbin@3.35.9': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on first few dependencies': {
      rule: {
        'jsbin@3.35.9 > handlebars@2.0.0': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match with multiple paths': {
      rule: {
        'express-hbs > handlebars > uglify-js': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
        'jsbin > handlebars > uglify-js': {
          reason: 'done this already',
          expires: '2016-03-01T19:53:46.310Z',
        },
      },
      match: true,
    },
    'match all paths with star': {
      rule: {
        '*': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match star at start': {
      rule: {
        '* > handlebars@2.0.0 > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match star in middle': {
      rule: {
        'jsbin@3.35.9 > * > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match star at end': {
      rule: {
        'jsbin > handlebars@2.0.0 > *': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match star at start and end': {
      rule: {
        '* > handlebars@2.0.0 > *': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match star for multiple dependencies': {
      rule: {
        '* > uglify-js': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on star version': {
      rule: {
        'jsbin@3.35.9 > handlebars@* > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on star dependency and star version': {
      rule: {
        '* > handlebars@* > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on multiple star versions': {
      rule: {
        '* > handlebars@* > uglify-js@*': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on version range': {
      rule: {
        'jsbin@3.35.9 > handlebars@>1.1.0 <2.1.0 > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on x range': {
      rule: {
        'jsbin@3.35.9 > handlebars@2.x > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'match on caret range': {
      rule: {
        'jsbin@3.35.9 > handlebars@^2.0.0 > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: true,
    },
    'no match on different path': {
      rule: {
        'nyc@11.9.0 > istanbul-lib-report@1.1.3 > path-parse@1.0.5': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: false,
    },
    'no match for different root': {
      rule: {
        'express-hbs > handlebars > uglify-js': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: false,
    },
    'no match on subpath': {
      rule: {
        'handlebars@2.0.0 > uglify-js@2.3.6': {
          reason: 'done this already',
          expires: '2016-03-01T19:53:46.310Z',
        },
      },
      match: false,
    },
    'no match on single dependency in path': {
      rule: {
        'handlebars@2.0.0': {
          reason: 'done this already',
          expires: '2016-03-01T19:53:46.310Z',
        },
      },
      match: false,
    },
    'no match for different root version': {
      rule: {
        'jsbin@1.0.0 > handlebars@2.0.0 > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: false,
    },
    'no match for different transitive version': {
      rule: {
        'jsbin@3.35.9 > handlebars@1.0.0 > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: false,
    },
    'no match with star': {
      rule: {
        '* > moment': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: false,
    },
    'no match on multiple stars': {
      rule: {
        '* > * > uglify-js@2.3.6': {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        },
      },
      match: false,
    },
  };

  for (var [name, test] of Object.entries(tt)) {
    t.test(name, (st) => {
      const pathMatch = policy.matchToRule(vuln, test.rule);

      if (test.match) {
        st.ok(pathMatch, 'vuln matches rule');
      } else {
        st.notOk(pathMatch, 'correctly does not match');
      }

      st.end();
    });
  }

  t.end();
});

test('matchToRule long', function (t) {
  const vuln = {
    from: [
      'test',
      'org.apache.kafka:kafka_2.13@2.7.1',
      'org.apache.zookeeper:zookeeper@3.5.9',
      'io.netty:netty-handler@4.1.50.Final',
      'io.netty:netty-codec@4.1.50.Final',
    ],
  };

  const tt = {
    one: {
      rule: {
        'org.apache.kafka:kafka_2.13@2.7.1 > org.apache.zookeeper:zookeeper@3.5.9 > io.netty:netty-handler@4.1.50.Final > io.netty:netty-codec@4.1.50.Final':
          {
            reason: 'None given',
            expires: '2016-03-01T19:49:50.633Z',
          },
      },
      match: true,
    },
    two: {
      rule: {
        'org.apache.kafka:kafka_2.13@2.7.1 > org.apache.zookeeper:zookeeper@>=3.5.0 <3.6.0 > io.netty:netty-handler@4.1.50.Final > io.netty:netty-codec@4.1.50.Final':
          {
            reason: 'done this already',
            expires: '2016-03-01T19:53:46.310Z',
          },
      },
      match: true,
    },
  };

  for (var [name, test] of Object.entries(tt)) {
    t.test(name, (st) => {
      const pathMatch = policy.matchToRule(vuln, test.rule);

      if (test.match) {
        st.ok(pathMatch, 'vuln matches rule');
      } else {
        st.notOk(pathMatch, 'correctly does not match');
      }

      st.end();
    });
  }

  t.end();
});

test('match (triggering not found)', function (t) {
  const vuln = require(fixtures + '/path-not-found.json');
  const rule = {
    'glue > hapi > joi > moment': {
      patched: '2016-02-26T16:19:06.050Z',
    },
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  t.equal(pathMatch, false, 'path does not match');
  t.end();
});

test('rule with git url as dependency', function (t) {
  const rule = {
    'patchable-vuln > qs': {
      patched: '2018-11-04T12:47:13.696Z',
    },
  };

  const pathMatch = policy.matchToRule(vulnWithGitUrl, rule);
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('exact match  does not match when path arrays are not equal', function (t) {
  const rule = {
    'a-dir/a-file.json': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.notOk(pathMatch, 'does not match when path arrays are not equal');
  t.end();
});

test('exact match  matches when path arrays are equal', function (t) {
  const rule = {
    'a-dir/a-file.json > foo > bar': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('exact match  matches when rule is *', function (t) {
  const rule = {
    '*': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('exact match  matches when path matches before *', function (t) {
  const rule = {
    'a-dir/a-file.json > *': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.ok(pathMatch, 'vuln matches rule');
  t.end();
});

test('exact match  does not match when path does not match before *', function (t) {
  const rule = {
    'a-dir/a-file.json > wrong > *': {},
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  t.notOk(pathMatch, 'correctly does not match');
  t.end();
});
