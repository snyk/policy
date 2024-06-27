import fs from 'fs';
import { describe, expect, test } from 'vitest';

import * as policy from '../../lib';
import { Rule, Vulnerability } from '../types';

const fixtures = __dirname + '/../fixtures';

const vulnWithGitUrl = JSON.parse(
  fs.readFileSync(fixtures + '/patch-with-git-url.json', 'utf8'),
);
const exactMatchVuln = {
  from: ['a-dir/a-file.json', 'foo', 'bar'],
} as Vulnerability;

describe('matchToRule', () => {
  const vuln = {
    from: [
      'projectName', // this is ignored
      'jsbin@3.35.9',
      'handlebars@2.0.0',
      'uglify-js@2.3.6',
    ],
  } as Vulnerability;

  test('match exact path', () => {
    const rule = {
      'jsbin@3.35.9 > handlebars@2.0.0 > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match without versions', () => {
    const rule = {
      'jsbin > handlebars > uglify-js': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match mixed version and versionless', () => {
    const rule = {
      'jsbin > handlebars@2.0.0 > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on only root dependency', () => {
    const rule = {
      'jsbin@3.35.9': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on first few dependencies', () => {
    const rule = {
      'jsbin@3.35.9 > handlebars@2.0.0': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match with multiple paths', () => {
    const rule = {
      'express-hbs > handlebars > uglify-js': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
      'jsbin > handlebars > uglify-js': {
        reason: 'done this already',
        expires: '2016-03-01T19:53:46.310Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match all paths with star', () => {
    const rule = {
      '*': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match star at start', () => {
    const rule = {
      '* > handlebars@2.0.0 > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match star in middle', () => {
    const rule = {
      'jsbin@3.35.9 > * > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match star at end', () => {
    const rule = {
      'jsbin > handlebars@2.0.0 > *': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match star at start and end', () => {
    const rule = {
      '* > handlebars@2.0.0 > *': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match star for multiple dependencies', () => {
    const rule = {
      '* > uglify-js': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on star version', () => {
    const rule = {
      'jsbin@3.35.9 > handlebars@* > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on star dependency and star version', () => {
    const rule = {
      '* > handlebars@* > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on multiple star versions', () => {
    const rule = {
      '* > handlebars@* > uglify-js@*': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on version range', () => {
    const rule = {
      'jsbin@3.35.9 > handlebars@>1.1.0 <2.1.0 > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on x range', () => {
    const rule = {
      'jsbin@3.35.9 > handlebars@2.x > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('match on caret range', () => {
    const rule = {
      'jsbin@3.35.9 > handlebars@^2.0.0 > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('no match on different path', () => {
    const rule = {
      'nyc@11.9.0 > istanbul-lib-report@1.1.3 > path-parse@1.0.5': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });

  test('no match for different root', () => {
    const rule = {
      'express-hbs > handlebars > uglify-js': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });

  test('no match on subpath', () => {
    const rule = {
      'handlebars@2.0.0 > uglify-js@2.3.6': {
        reason: 'done this already',
        expires: '2016-03-01T19:53:46.310Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });

  test('no match on single dependency in path', () => {
    const rule = {
      'handlebars@2.0.0': {
        reason: 'done this already',
        expires: '2016-03-01T19:53:46.310Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });

  test('no match for different root version', () => {
    const rule = {
      'jsbin@1.0.0 > handlebars@2.0.0 > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });

  test('no match for different transitive version', () => {
    const rule = {
      'jsbin@3.35.9 > handlebars@1.0.0 > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });

  test('no match with star', () => {
    const rule = {
      '* > moment': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });

  test('no match on multiple stars', () => {
    const rule = {
      '* > * > uglify-js@2.3.6': {
        reason: 'None given',
        expires: '2016-03-01T19:49:50.633Z',
      } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeFalsy();
  });
});

describe('matchToRule long', () => {
  const vuln = {
    from: [
      'test',
      'org.apache.kafka:kafka_2.13@2.7.1',
      'org.apache.zookeeper:zookeeper@3.5.9',
      'io.netty:netty-handler@4.1.50.Final',
      'io.netty:netty-codec@4.1.50.Final',
    ],
  } as Vulnerability;

  test('one', () => {
    const rule = {
      'org.apache.kafka:kafka_2.13@2.7.1 > org.apache.zookeeper:zookeeper@3.5.9 > io.netty:netty-handler@4.1.50.Final > io.netty:netty-codec@4.1.50.Final':
        {
          reason: 'None given',
          expires: '2016-03-01T19:49:50.633Z',
        } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });

  test('two', () => {
    const rule = {
      'org.apache.kafka:kafka_2.13@2.7.1 > org.apache.zookeeper:zookeeper@>=3.5.0 <3.6.0 > io.netty:netty-handler@4.1.50.Final > io.netty:netty-codec@4.1.50.Final':
        {
          reason: 'done this already',
          expires: '2016-03-01T19:53:46.310Z',
        } as Rule,
    };

    const pathMatch = policy.matchToRule(vuln, rule);
    expect(pathMatch).toBeTruthy();
  });
});

test('match (triggering not found)', () => {
  const vuln = require(fixtures + '/path-not-found.json');
  const rule = {
    'glue > hapi > joi > moment': {
      patched: '2016-02-26T16:19:06.050Z',
    } as Rule,
  };

  const pathMatch = policy.matchToRule(vuln, rule);
  expect(pathMatch).toBe(false);
});

test('rule with git url as dependency', () => {
  const rule = {
    'patchable-vuln > qs': {
      patched: '2018-11-04T12:47:13.696Z',
    } as Rule,
  };

  const pathMatch = policy.matchToRule(vulnWithGitUrl, rule);
  expect(pathMatch).toBeTruthy();
});

test('exact match  does not match when path arrays are not equal', () => {
  const rule = {
    'a-dir/a-file.json': {} as Rule,
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  expect(pathMatch).toBeFalsy();
});

test('exact match  matches when path arrays are equal', () => {
  const rule = {
    'a-dir/a-file.json > foo > bar': {} as Rule,
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  expect(pathMatch).toBeTruthy();
});

test('exact match  matches when rule is *', () => {
  const rule = {
    '*': {} as Rule,
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  expect(pathMatch).toBeTruthy();
});

test('exact match  matches when path matches before *', () => {
  const rule = {
    'a-dir/a-file.json > *': {} as Rule,
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  expect(pathMatch).toBeTruthy();
});

test('exact match  does not match when path does not match before *', () => {
  const rule = {
    'a-dir/a-file.json > wrong > *': {} as Rule,
  };

  const pathMatch = policy.matchToRule(exactMatchVuln, rule, 'exact');
  expect(pathMatch).toBeFalsy();
});
