import * as yaml from 'js-yaml';
import cloneDeep from 'lodash.clonedeep';
import * as semver from 'semver';
import { latestVersion } from '../';
import { version as versionFromPackageJson } from '../../package.json';
import { isObject } from '../types';
import addComments from './add-comments';
import v1 from './v1';

export { default as demunge } from './demunge';
export { imports as import, exportsFn as export, packageVersion as version };

const defaultPolicyVersion = 'v1';
const packageVersion = version();

interface versioned extends Record<string, unknown> {
  version: string;
}

const parsers = {
  v1,
};

function imports(rawYaml = '') {
  const yamlData = yaml.load(rawYaml);
  const data = isObject(yamlData) ? yamlData : {};

  const isVersioned = (
    yamlObj: Record<string, unknown>
  ): yamlObj is versioned => typeof yamlObj.version === 'string';

  let version = isVersioned(data) ? data.version : defaultPolicyVersion;

  if (version === 'v1') {
    version = 'v1.0.0';
  }

  data.version = version;
  const parser = parsers['v' + semver.major(version.substr(1))];

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
  data.version = latestVersion();
  // put inline comments into the exported yaml file
  return addComments(yaml.dump(data));
}

/**
 * @deprecated
 */
function version() {
  if (versionFromPackageJson && versionFromPackageJson !== '0.0.0') {
    return 'v' + versionFromPackageJson;
  }

  return 'v1.0.0';
}
