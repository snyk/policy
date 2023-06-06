import { PathObj, Policy } from '../types';

export default demunge;

type PathRule = {
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

interface VulnRules {
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

interface DemungedResults {
  exclude: VulnRules[];
  ignore: VulnRules[];
  patch: VulnRules[];
  version: string;
}

/**
 * Demunges the given policy object.
 * @param policy  The policy object to demunge
 * @param apiRoot The root URL of the Snyk API
 * @returns The demunged policy object
 */
function demunge(policy: Policy, apiRoot = '') {
  const res = ['ignore', 'patch', 'exclude'].reduce((acc, type) => {
    acc[type] = policy[type]
      ? Object.keys(policy[type]).map((id) => {
          const paths = policy[type][id].map(
            (pathObj: PathObj | string): PathRule => {
              if (type === 'exclude' && typeof pathObj === 'string') {
                return {
                  path: pathObj,
                } as PathRule;
              }

              const path = Object.keys(pathObj).pop()!; // eslint-disable-line @typescript-eslint/no-non-null-assertion
              const res = {
                path: path,
              } as PathRule;
              if (type === 'ignore' || type === 'exclude') {
                res.reason = pathObj[path].reason;
                res.expires =
                  pathObj[path].expires && new Date(pathObj[path].expires);
                res.disregardIfFixable = pathObj[path].disregardIfFixable;
              }

              return res;
            }
          );
          return {
            id: id,
            url: apiRoot + '/vuln/' + id,
            paths: paths,
          } as VulnRules;
        })
      : [];
    return acc;
  }, {} as DemungedResults);

  res.version = policy.version;

  return res;
}
