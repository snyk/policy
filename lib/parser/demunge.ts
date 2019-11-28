import { Policy, PolicyTypeName } from '../types';

export function demunge(policy: Policy, apiRoot?: string) {
  if (!apiRoot) {
    apiRoot = '';
  }

  return ['ignore', 'patch'].reduce(
    (acc, type: PolicyTypeName) => {
      acc[type] = policy[type]
        ? Object.keys(policy[type]).map(function(id) {
            const paths = policy[type][id].map(function(pathObj) {
              const path = Object.keys(pathObj).pop();
              const res: any = {
                path: path,
              };
              if (type === 'ignore') {
                res.reason = pathObj[path].reason;
                res.expires =
                  pathObj[path].expires && new Date(pathObj[path].expires);
                res.disregardIfFixable = pathObj[path].disregardIfFixable;
              }

              return res;
            });
            return {
              id: id,
              url: apiRoot + '/vuln/' + id,
              paths: paths,
            };
          })
        : [];
      return acc;
    },
    { version: policy.version } as {
      ignore?: any[];
      patch?: any[];
      version: string;
    },
  );
}
