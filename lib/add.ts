export default add;

import * as emailValidator from 'email-validator';

import { AddRuleOptions, PathObj, Policy, ReasonType, Rule } from './types';

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
  options: AddRuleOptions,
) {
  if (type !== 'ignore' && type !== 'patch') {
    throw new Error('policy.add: unknown type "' + type + '" to add to');
  }

  if (!options || !options.id || !options.path) {
    throw new Error('policy.add: required option props { id, path }');
  }

  const id = options.id;
  const path = options.path;

  if (
    options.reasonType &&
    validReasonTypes.indexOf(options.reasonType) === -1
  ) {
    throw new Error('invalid reasonType ' + options.reasonType);
  }

  if (options.ignoredBy) {
    if (typeof options.ignoredBy !== 'object') {
      throw new Error('ignoredBy must be an object');
    }

    if (!emailValidator.validate(options.ignoredBy.email)) {
      throw new Error('ignoredBy.email must be a valid email address');
    }
  }

  const data = { ...options } as Rule;

  if (!policy[type][id]) {
    policy[type][id] = [];
  }

  const rule = {} as PathObj;
  rule[path] = data;

  policy[type][id].push(rule);

  return policy;
}
