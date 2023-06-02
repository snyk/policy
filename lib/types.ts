export type MatchStrategy = 'packageManager' | 'exact';

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
 *   "sqlite > sqlite3 > node-pre-gyp > request > hawk": {
 *     "reason": "None given",
 *     "expires": "2016-03-01T14:30:04.136Z"
 *   }
 * }
 */
export type PathObj = Record<string, Rule>;

export interface Policy {
  __filename: string;
  __created: number;
  __modified: number;

  ignore: RuleSet;
  patch: RuleSet;
  suggest: RuleSet;
  exclude?: RuleSet;

  failThreshold: Severity;
  skipVerifyPatch: boolean;
  version: string;
}

/**
 * @example
 * {
 *   "reason": "None given",
 *   "expires": "2016-03-01T14:30:04.136Z"
 * }
 */
export interface Rule {
  created: Date | string;
  disregardIfFixable: boolean;
  expires?: Date | string;
  ignoredBy: {
    email: string;
  };
  path: string[];
  reason: string;
  reasonType: string;
  source: string;
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
  ignore: Rule;
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
  upgradePath: any[];

  isPatchable: boolean;
  patches: any[];

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
  ok: boolean;

  /**
   * The vulnerabilities found in the project.
   */
  vulnerabilities: Vulnerability[];
}
