import {
  PathObj,
  Policy,
  PolicyError,
  Rule,
  RuleSet,
  Severity,
} from '../types';

export { imports as default, needsFixing };

interface Fix {
  id: string; // vulnID
  key: string;
  rule: Rule;
}

/**
 * Imports the given policy from a YAML object.
 * @param policy (*mutates!*) the YAML policy object to import
 * @returns the imported policy
 * @throws if an old format is detected
 */
function imports(policy: Record<string, unknown>) {
  // eventually we'll have v2 which will point to latestParser, and v1 will
  // need to process the old form of data and upgrade it to v2 structure
  if (!policy.ignore) {
    policy.ignore = {};
  }

  if (!policy.patch) {
    policy.patch = {};
  }

  const isObject = (v: unknown): v is Record<string, unknown> =>
    Object.prototype.toString.call(v) === '[object Object]'; // typeof returns true for arrays and other types

  if (isObject(policy.patch)) {
    for (const id in policy.patch) {
      if (!Array.isArray(policy.patch[id])) {
        delete policy.patch[id];
      }
    }
  }

  checkForOldFormat(policy.ignore); // this is only an old issue on ignores
  validate(policy.ignore as RuleSet);
  validate(policy.patch as RuleSet);

  policy.failThreshold = getFailThreshold(policy);
  if (!policy.failThreshold) {
    // throw it away if it's not set
    delete policy.failThreshold;
  }

  return policy as unknown as Policy;
}

/**
 * Checks to see if the given rule set is in the old format.
 * @param ruleSet the rule set to check
 * @throws if an old format is passed
 */
function checkForOldFormat(ruleSet: unknown) {
  // this is a cursory test to ensure that we're working with a `.snyk` format
  // that we recognize. if the property is an object, then it's the early
  // alpha format, and we'll throw
  if (isObject(ruleSet)) {
    for (const id in ruleSet) {
      if (!Array.isArray(ruleSet[id])) {
        // create an error and add a code field to it without using `any`
        // const error = new Error('old, unsupported .snyk format detected');
        // error.code = 'OLD_DOTFILE_FORMAT';
        // throw error;
      }
    }
  }
}

/**
 * Validates the given rule set, and fixes it if necessary.
 * @param ruleSet (*mutates!*) the rule set to validate
 */
function validate(ruleSet: RuleSet) {
  const fix = needsFixing(ruleSet);

  if (fix) {
    fix.forEach((item) => {
      const o = {} as PathObj;
      o[item.key] = item.rule;
      ruleSet[item.id].push(o);
    });
  }
}

/**
 * Checks to see if the given rule set needs fixing.
 * @param ruleSet the rule set to check
 * @returns `false` if no fixes are needed, otherwise an array of fixes
 */
function needsFixing(ruleSet: RuleSet) {
  const move: Fix[] = [];

  for (const id in ruleSet) {
    for (const rule of ruleSet[id]) {
      const keys = Object.keys(rule);
      keys.shift(); // drop the first

      // no idea how this could happen!
      // eslint-disable-next-line
      if ((keys as any) === 0) {
        return;
      }

      // this means our policy has become corrupted, and we need to move
      // the additional keys into their own position in the policy
      keys.forEach((key) => {
        move.push({
          id: id,
          key: key,
          rule: rule[key],
        });
        delete rule[key];
      });
    }
  }

  return move.length ? move : false;
}

/**
 * Returns `failThreshold` in the provided policy allowing for silly typos.
 * @param policy the project's policy document
 * @returns the policies failure threshold or `null` if not found
 * @throws if an unknown severity is found
 */
function getFailThreshold(policy: Record<string, unknown>): Severity | null {
  const threshold = [
    'failThreshold',
    'fail_threshold',
    'failthreshold',
    'threshold',
    'fail_threshhold',
  ]
    .map((key) => policy[key])
    .find((v) => v);

  if (!threshold || typeof threshold !== 'string') {
    return null;
  }

  const strThreshold = threshold.toLowerCase().trim();

  if (!isSeverity(strThreshold)) {
    throw new PolicyError(
      'unknown threshold value "' + strThreshold + '"',
      'POLICY_BAD_THRESHOLD'
    );
  }

  return strThreshold;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  Object.prototype.toString.call(v) === '[object Object]'; // typeof returns true for arrays and other types

function isSeverity(s: string): s is Severity {
  const valid = ['high', 'medium', 'low'];
  return valid.indexOf(s) > -1;
}
