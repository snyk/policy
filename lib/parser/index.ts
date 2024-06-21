import * as yaml from 'js-yaml';
import cloneDeep from 'lodash.clonedeep';
import * as semver from 'semver';

import { latestVersion } from '../policy';
import { Policy, isObject } from '../types';
import addComments from './add-comments';
import v1 from './v1';

export { default as demunge } from './demunge';
export { imports as import, exportsFn as export };

const defaultPolicyVersion = 'v1';

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
    yamlObj: Record<string, unknown>,
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
  const data = cloneDeep(policy);

  // remove any private information on the policy
  for (const key in data) {
    const k = key as keyof Policy;

    if (k.indexOf('__') === 0) {
      delete data[k];
    }

    if (data[k] == null) {
      // jshint ignore:line
      delete data[k];
    }

    // strip helper functions
    if (typeof data[k] === 'function') {
      delete data[k];
    }
  }

  // ensure we always update the version of the policy format
  data.version = latestVersion();
  // put inline comments into the exported yaml file
  return addComments(yaml.dump(data));
}
