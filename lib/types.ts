export interface AddRuleOptions extends Rule {
  /**
   * The id of the vulnerability to which the rule applies.
   */
  id: string;

  /**
   * The path or the dependency to which the rule applies.
   */
  path: string;

  reasonType?: ReasonType;
}

export type ExcludeRuleSet = Record<PatternGroup, (string | PathObj)[]>;

export interface FilteredRule extends Rule {
  path: string[];
}

export interface FilteredVulnerability extends Vulnerability {
  filtered?: {
    ignored?: FilteredRule[];
    patches?: FilteredRule[];
  };
  note?: string;
}

export interface FilteredVulns {
  ok: boolean;

  vulnerabilities: FilteredVulnerability[];

  filtered?: {
    ignore: Vulnerability[];
    patch: Vulnerability[];
  };
}

export type MatchStrategy = 'packageManager' | 'exact';

export interface MetaRule extends Rule {
  path: string;
}

/**
 * A dependency package.
 */
export interface Package {
  name: string;
  version: string;
}

/**
 * @example
 * {
 *  "urls": [
 *    "https://raw.githubusercontent.com/Snyk/vulndb/snapshots/master/patches/npm/handlebars/20151207/handlebars_0.patch"
 *  ],
 *  "version": "<4.0.0 >=3.0.2",
 *  "modificationTime": "2015-12-14T23:52:16.811Z",
 *  "comments": [
 *    "https://github.com/wycats/handlebars.js/commit/83b8e846a3569bd366cf0b6bdc1e4604d1a2077e"
 *  ],
 *  "id": "patch:npm:handlebars:20151207:0"
 * }
 */
interface Patch {
  urls: string[];
  version: string;
  modificationTime: string;
  comments: string[];
  id: string;
}

/**
 * @example
 * {
 *   "sqlite > sqlite3 > node-pre-gyp > request > hawk": {
 *     "reason": "None given",
 *     "expires": "2016-03-01T14:30:04.136Z"
 *   }
 * }
 */
export type PathObj = Record<string, Rule>;

export type PatternGroup = 'global' | 'code' | 'iac-drift';

export interface Policy {
  __filename: string | null;
  __created: Date | number;
  __modified: Date | number;

  ignore: RuleSet;
  patch: RuleSet;
  suggest: RuleSet;
  exclude?: ExcludeRuleSet;

  failThreshold: Severity;
  skipVerifyPatch: boolean;
  version: string;

  add: (type: 'ignore' | 'patch', options: AddRuleOptions) => Policy;
  addExclude: (pattern: string, group?: PatternGroup, options?: Rule) => void;
  addIgnore: (options: AddRuleOptions) => Policy;
  addPatch: (options: AddRuleOptions) => Policy;
  filter: (
    vulns: VulnsObject,
    root?: string,
    matchStrategy?: MatchStrategy
  ) => FilteredVulns;
}

export class PolicyError extends Error {
  code?: string;

  constructor(message: string, code?: string) {
    super(message);
    Object.setPrototypeOf(this, PolicyError.prototype);
    this.code = code;
  }
}

export type ReasonType = 'not-vulnerable' | 'wont-fix' | 'temporary-ignore';

/**
 * @example
 * {
 *   "reason": "None given",
 *   "expires": "2016-03-01T14:30:04.136Z"
 * }
 */
export interface Rule {
  created?: Date;
  disregardIfFixable?: boolean;
  expires?: string | Date;
  ignoredBy?: {
    email: string;
  };
  reason?: string;
  reasonType?: ReasonType;
  source?: string;
  from?: string;
  patched?: string;
}

/**
 * @example
 * {
 *   "npm:hawk:20160119": [
 *     {
 *       "sqlite > sqlite3 > node-pre-gyp > request > hawk": {
 *         "reason": "None given",
 *         "expires": "2016-03-01T14:30:04.136Z"
 *       }
 *     }
 *   ],
 *   "npm:is-my-json-valid:20160118": [
 *     {
 *       "sqlite > sqlite3 > node-pre-gyp > request > har-validator > is-my-json-valid": {
 *         "reason": "None given",
 *         "expires": "2016-03-01T14:30:04.136Z"
 *       }
 *     }
 *   ],
 * }
 */
export type RuleSet = Record<string, PathObj[]>;

export interface SecurityPolicyMetaData {
  ignore: MetaRule;
}

/**
 * Vulnerability severity.
 */
export type Severity = 'high' | 'medium' | 'low';

export interface Vulnerability {
  __filename?: string;
  id: string;
  severity: string;

  /**
   * The dependency path in which the vulnerability was introduced. This should include the project
   * itself.
   */
  from: string[];

  isUpgradable: boolean;
  upgradePath: (string | false)[];

  isPatchable: boolean;
  patches: Patch[];

  securityPolicyMetaData: SecurityPolicyMetaData;
}

export interface VulnRule extends Rule {
  /**
   * The vulnerability ID.
   */
  id: string;

  /**
   * The type of rule.
   */
  type: 'ignore' | 'patch';

  /**
   * An array of dependencies (`package@version`) in which the vulnerability was introduced.
   */
  rule: Array<string>;
}

export interface VulnsObject {
  /**
   * If all the vulns are stripped because of the policy, then the `ok` bool is set to `true`.
   */
  ok?: boolean;

  /**
   * The vulnerabilities found in the project.
   */
  vulnerabilities: Vulnerability[];
}

/**
 * Returns true if the value is an object. This is a more reliable check than `typeof` or
 * `instanceof`, because `typeof null` is `object` and `typeof []` is `object` which is not what
 * we want.
 * @param v The value to check.
 * @returns True if the value is an object.
 */
export function isObject(v: unknown): v is Record<string, unknown> {
  return Object.prototype.toString.call(v) === '[object Object]';
}

/**
 * Returns true if the error is a NodeJS error.
 * @param value The value to check.
 */
export function isNodeError(value: unknown): value is NodeJS.ErrnoException {
  return value instanceof Error;
}
