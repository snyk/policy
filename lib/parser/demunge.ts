import {
  DemungedResults,
  PathObj,
  PathRule,
  Policy,
  VulnRules,
} from '../types';

export default demunge;

/**
 * Demunges the given policy object.
 * @param policy  The policy object to demunge
 * @param apiRoot The root URL of the Snyk API
 * @returns The demunged policy object
 */
function demunge(policy: Policy, apiRoot = '') {
  const res = (
    ['ignore', 'patch', 'exclude'] as ('ignore' | 'patch' | 'exclude')[]
  ).reduce((acc, type) => {
    const ruleSet = policy[type];
    acc[type] = ruleSet
      ? Object.keys(ruleSet).map((id) => {
          //eslint-disable-next-line @typescript-eslint/no-explicit-any
          const paths = (ruleSet as Record<string, any>)[id].map(
            (pathOrPathObj: PathObj | string): PathRule => {
              if (type === 'exclude' && typeof pathOrPathObj === 'string') {
                return {
                  path: pathOrPathObj,
                } as PathRule;
              }

              const pathObj = pathOrPathObj as PathObj; // we should error if it's not an object

              const path = Object.keys(pathObj).pop()!; // eslint-disable-line @typescript-eslint/no-non-null-assertion
              const res = {
                path: path,
              } as PathRule;
              if (type === 'ignore' || type === 'exclude') {
                const expires = pathObj[path].expires;
                res.reason = pathObj[path].reason;
                res.expires = expires ? new Date(expires) : undefined;
                res.disregardIfFixable = pathObj[path].disregardIfFixable;
              }

              return res;
            },
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
