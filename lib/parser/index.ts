import * as yaml from 'js-yaml';
import cloneDeep from 'lodash.clonedeep';
import * as semver from 'semver';
import { version as versionFromPackageJson } from '../../package.json';
import addComments from './add-comments';
import v1 from './v1';

export { default as demunge } from './demunge';
export { imports as import, exportsFn as export, packageVersion as version };

const packageVersion = version();

const parsers = {
  v1,
};

function imports(rawYaml = '') {
  let data = yaml.safeLoad(rawYaml);

  if (!data || typeof data !== 'object') {
    data = {};
  }

  if (!data.version) {
    data.version = 'v1';
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

// Compiler reserves name 'exports' in top level scope of a module
function exportsFn(policy) {
  const data = cloneDeep(policy);

  // remove any private information on the policy
  Object.keys(data).map(function (key) {
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
  data.version = version();
  // put inline comments into the exported yaml file
  return addComments(yaml.safeDump(data));
}

function version() {
  if (versionFromPackageJson && versionFromPackageJson !== '0.0.0') {
    return 'v' + versionFromPackageJson;
  }

  return 'v1.0.0';
}
