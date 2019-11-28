// eventually we'll have v2 which will point to latestParser, and v1 will
// need to process the old form of data and upgrade it to v2 structure
import { Policy, SubPolicy } from '../types';

export function imports(policy: Policy): Policy {
  if (!policy.ignore) {
    policy.ignore = {};
  }

  if (!policy.patch) {
    policy.patch = {};
  }

  Object.keys(policy.patch).forEach(function(id) {
    if (!Array.isArray(policy.patch[id])) {
      delete policy.patch[id];
    }
  });

  checkForOldFormat(policy.ignore); // this is only an old issue on ignores
  validate(policy.ignore);
  validate(policy.patch);

  policy.failThreshold = getFailThreshold(policy);
  if (!policy.failThreshold) {
    // throw it away if it's not set
    delete policy.failThreshold;
  }

  return policy;
}

function checkForOldFormat(ignore: SubPolicy): void {
  // this is a cursory test to ensure that we're working with a snyk format
  // that we recognise. if the property is an object, then it's the early
  // alpha format, and we'll throw
  Object.keys(ignore).forEach(function(id: string): void {
    if (!Array.isArray(ignore[id])) {
      const error: any = new Error('old, unsupported .snyk format detected');
      error.code = 'OLD_DOTFILE_FORMAT';
      throw error;
    }
  });
}

function validate(policy): void {
  needsFixing(policy).forEach((item: Fix): void => {
    const o = {};
    o[item.key] = item.rule;
    policy[item.id].push(o);
  });
}

export interface Fix {
  id: string;
  key: string;
  rule: unknown;
}

export function needsFixing(policy): Fix[] {
  const move: Fix[] = [];
  Object.keys(policy).forEach(function(id) {
    policy[id].forEach(function(rule) {
      const keys = Object.keys(rule);
      keys.shift(); // drop the first

      if (keys.length === 0) {
        return;
      }

      // this means our policy has become corrupted, and we need to move
      // the additional keys into their own position in the policy
      keys.forEach(function(key) {
        move.push({
          id: id,
          key: key,
          rule: rule[key],
        });
        delete rule[key];
      });
    });
  });

  return move;
}

function getFailThreshold(policy: Policy): string | null {
  let threshold: string | null = null;

  // pluck the value out, and support all sorts of silly typos
  [
    'failThreshold',
    'fail_threshold',
    'failthreshold',
    'threshold',
    'fail_threshhold',
  ].some(function(key) {
    // if we have the value, set it and return it - which will exit loop
    return (threshold = policy[key] || null); // jshint ignore:line
  });

  if (!threshold) {
    return null;
  }

  const valid = ['high', 'medium', 'low'];

  threshold = threshold.toLowerCase().trim();

  if (valid.indexOf(threshold) === -1) {
    const error: any = new Error('unknown threshold value "' + threshold + '"');
    error.code = 'POLICY_BAD_THRESHOLD';
    throw error;
  }

  return threshold;
}
