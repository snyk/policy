export default add;

import newDebug from 'debug';
import * as emailValidator from 'email-validator';

import { AddRuleOptions, PathObj, Policy, ReasonType, Rule } from './types';

const debug = newDebug('snyk:policy');
const validReasonTypes: ReasonType[] = [
  'not-vulnerable',
  'wont-fix',
  'temporary-ignore',
];

/**
 * Adds an ignore or patch rule to the policy.
 * @param policy (*mutates!*) the policy object to add the rule to
 * @param type the type of rule to add
 * @param options the options for the rule
 * @returns the policy object
 */
function add(
  policy: Policy,
  type: 'ignore' | 'patch',
  options: AddRuleOptions
) {
  if (type !== 'ignore' && type !== 'patch') {
    throw new Error('policy.add: unknown type "' + type + '" to add to');
  }

  if (!options || !options.id || !options.path) {
    throw new Error('policy.add: required option props { id, path }');
  }

  const id = options.id;
  const path = options.path;
  const data = Object.keys(options).reduce((acc, curr) => {
    if (curr === 'id' || curr === 'path') {
      return acc;
    }

    if (
      curr === 'reasonType' &&
      options.reasonType &&
      validReasonTypes.indexOf(options.reasonType) === -1
    ) {
      throw new Error('invalid reasonType ' + options[curr]);
    }

    if (curr === 'ignoredBy' && options.ignoredBy) {
      if (typeof options.ignoredBy !== 'object') {
        throw new Error('ignoredBy must be an object');
      }

      if (!emailValidator.validate(options.ignoredBy.email)) {
        throw new Error('ignoredBy.email must be a valid email address');
      }
    }

    acc[curr] = options[curr];
    return acc;
  }, {} as Rule);

  if (!policy[type][id]) {
    policy[type][id] = [];
  }

  if (policy[type][id][path]) {
    debug('policy.add: path already exists', policy[type][id][path]);
  }

  const rule = {} as PathObj;
  rule[path] = data;

  policy[type][id].push(rule);

  return policy;
}
