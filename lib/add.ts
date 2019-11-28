import * as debugModule from 'debug';
import * as emailValidator from 'email-validator';
import { Policy, PolicyTypeName } from './types';

const debug = debugModule('snyk:policy');

const validReasonTypes = ['not-vulnerable', 'wont-fix', 'temporary-ignore'];

export interface AddOptions {
  id: string;
  path: string;
  [key: string]: unknown;
}

export function add<P extends Policy>(
  policy: P,
  type: PolicyTypeName,
  options: AddOptions,
): P {
  if (type !== 'ignore' && type !== 'patch') {
    throw new Error('policy.add: unknown type "' + type + '" to add to');
  }

  if (!options || !options.id || !options.path) {
    throw new Error('policy.add: required option props { id, path }');
  }

  const id = options.id;
  const path = options.path;
  const data = Object.keys(options).reduce(function(acc, curr) {
    if (curr === 'id' || curr === 'path') {
      return acc;
    }

    if (
      curr === 'reasonType' &&
      validReasonTypes.indexOf(options[curr] as string) === -1
    ) {
      throw new Error('invalid reasonType ' + options[curr]);
    }

    if (curr === 'ignoredBy') {
      if (typeof options[curr] !== 'object') {
        throw new Error('ignoredBy must be an object');
      }

      if (!emailValidator.validate((options[curr] as any).email)) {
        throw new Error('ignoredBy.email must be a valid email address');
      }
    }

    acc[curr] = options[curr];
    return acc;
  }, {});

  if (!policy[type][id]) {
    policy[type][id] = [];
  }

  /* istanbul ignore if */
  if (policy[type][id][path]) {
    debug('policy.add: path already exists', policy[type][id][path]);
  }

  const rule = {};
  rule[path] = data;

  policy[type][id].push(rule);

  return policy;
}
