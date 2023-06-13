export interface AddRuleOptions extends Rule {
  /**
   * The id of the vulnerability to which the rule applies.
   */
  id: string;

  /**
   * The path or the dependency to which the rule applies.
   */
  path: string;

  ignoredBy?: {
    email: string
  }

  patched?: string;
  reasonType?: ReasonType;
}

export interface DemungedResults {
  exclude: VulnRules[];
  ignore: VulnRules[];
  patch: VulnRules[];
  version: string;
}

export type ExcludeRuleSet = Record<PatternGroup, (string | PathObj)[]>;

export interface PatchMetaData {
  patched: string;
}

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

export interface FilteredVulnerabilityReport {
  ok: boolean;

  vulnerabilities: FilteredVulnerability[];

  filtered?: {
    ignore: Vulnerability[];
    patch: Vulnerability[];
  };
}

export type MatchStrategy = 'packageManager' | 'exact';

export interface MetaRule extends Rule {
  path: string[] | { module: string; url?: string; }[];
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
  urls?: string[];
  version?: string;
  modificationTime: string;
  comments?: string[];
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

export type PathRule = {
  /**
   * The path to which the rule is applied.
   */
  path: string;

  /**
   * If true, the rule is disregarded if the vulnerability is fixable.
   */
  disregardIfFixable?: boolean;

  /**
   * The date the rule expires.
   */
  expires?: Date;

  /**
   * The reason for the rule.
   */
  reason?: string;
};

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
  demunge: (apiRoot?: string) => DemungedResults;
  filter: (
    vulns: VulnerabilityReport,
    root?: string,
    matchStrategy?: MatchStrategy
  ) => FilteredVulnerabilityReport;
  save: (root?: string | undefined, spinner?: Spinner) => Promise<void>;
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
    email?: string;
    name?: string;
  };
  reason?: string;
  reasonType?: ReasonType;
  source?: string;
  from?: string;
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
  ignore?: MetaRule;
}

/**
 * Vulnerability severity.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Spinner = {
  (label: string): Promise<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  clear: (label: string) => Promise<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
};

export interface Vulnerability {
  __filename?: string;
  readonly id: string;
  severity: Severity;

  /**
   * The dependency path in which the vulnerability was introduced. A chain of the packages leading
   * to the culprit, in the `name` or `name@version` format.This should include the project
   * itself.
   * The element [0] is the root package (the scanned project). The element [1] is a top-level
   * dependency etc.
   */
  from: string[];

  isUpgradable: boolean;

  /**
   * A possible upgrade remediation path. Mirrors the `from` field above, but contains upgraded
   * versions. The element [0] is usually `false` and is of no use.  If the element [1] is false,
   * there's no valid complete upgrade path yet.
   */
  upgradePath: (string | boolean)[];

  isPatchable: boolean;

  patches: Patch[];

  securityPolicyMetaData?: SecurityPolicyMetaData;
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

export interface VulnerabilityReport {
  /**
   * If all the vulns are stripped because of the policy, then the `ok` bool is set to `true`.
   */
  ok?: boolean;

  /**
   * The vulnerabilities found in the project.
   */
  vulnerabilities: Vulnerability[];
}

export interface VulnRules {
  /**
   * The vulnerability ID.
   */
  id: string; // vulnID

  /**
   * The URL to the vulnerability on the Snyk website.
   */
  url: string;

  /**
   * The vulnerability's rules with paths to ignore.
   */
  paths: PathRule[];
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
