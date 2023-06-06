import * as yaml from 'js-yaml';
import cloneDeep from 'lodash.clonedeep';
import * as semver from 'semver';

import { version as versionFromPackageJson } from '../../package.json';
import { latestVersion } from '../';
import { Policy, isObject } from '../types';
import addComments from './add-comments';
import v1 from './v1';

export { default as demunge } from './demunge';
export { imports as import, exportsFn as export, packageVersion as version };

const defaultPolicyVersion = 'v1';
const packageVersion = version();

type parser = (policy: Record<string, unknown>) => Policy;

interface versioned extends Record<string, unknown> {
  version: string;
}

const parsers: Record<string, parser> = {
  v1,
};

/**
 * Imports the given policy from a YAML string.
 * @param rawYaml the YAML policy string to import
 * @returns the imported policy
 */
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

/**
 * Exports the given policy to a YAML string.
 * @param policy the policy to export
 * @returns the exported policy as a YAML string
 */
function exportsFn(policy: Policy) {
  // Compiler reserves name 'exports' in top level scope of a module
  const data = cloneDeep(policy) as Policy;

  // remove any private information on the policy
  for (const key in data) {
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
  }

  // ensure we always update the version of the policy format
  data.version = latestVersion();
  // put inline comments into the exported yaml file
  return addComments(yaml.dump(data));
}

/**
 * @deprecated default version of the imported policy file is now always v1 and not coupled to the
 * current library version.
 */
function version() {
  if (versionFromPackageJson && versionFromPackageJson !== '0.0.0') {
    return 'v' + versionFromPackageJson;
  }

  return 'v1.0.0';
}
