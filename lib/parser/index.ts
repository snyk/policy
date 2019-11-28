import * as path from 'path';
import { cloneDeep } from 'lodash';
import * as semver from 'semver';
import * as yaml from 'js-yaml';
import { addComments } from './add-comments';
import { imports as v1 } from './v1';

const parsers = { v1 };

export const version = readOurVersion();

export function imports(rawYaml?) {
  let data = yaml.safeLoad(rawYaml || '');

  if (!data || typeof data !== 'object') {
    data = {};
  }

  if (!data.version) {
    data.version = version;
  }

  if (data.version === 'v1') {
    data.version = 'v1.0.0';
  }

  const parser = parsers['v' + semver.major(data.version.substr(1))];

  if (!parser) {
    throw new Error('unsupported version: ' + data.version);
  }

  return parser(data);
}

export function exportsOf(policy) {
  const data = cloneDeep(policy);

  // remove any private information on the policy
  Object.keys(data).map(function(key) {
    if (key.indexOf('__') === 0) {
      delete data[key];
    }

    if (data[key] == null) {
      // jshint ignore:line
      delete data[key];
    }

    // strip helper functions
    if (typeof data[key] === 'function') {
      delete data[key];
    }
  });

  // ensure we always update the version of the policy format
  data.version = version;
  // put inline comments into the exported yaml file
  return addComments(yaml.safeDump(data));
}

function readOurVersion() {
  const filename = path.resolve(__dirname, '..', '..', 'package.json');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const version = require(filename).version;

  if (version && version !== '0.0.0') {
    return 'v' + version;
  }

  return 'v1.0.0';
}
