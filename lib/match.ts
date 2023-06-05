import newDebug from 'debug';
import * as semver from 'semver';

import { parsePackageString as moduleToObject } from 'snyk-module';

import {
  MatchStrategy,
  Package,
  PathObj,
  Policy,
  VulnRule,
  Vulnerability,
} from './types';

export { matchToRule, getByVuln };

const debug = newDebug('snyk:policy');
const debugPolicy = newDebug('snyk:protect');

/**
 * matchPath will take the array of dependencies that a vulnerability came from and try to match it
 * to a rule `path`.
 *
 * The path will look like this: `express-hbs@0.8.4 > handlebars@3.0.3 > uglify-js@2.3.6`.
 * Note that the root package is never part of the path (i.e. `jsbin@3.11.31`).
 * The path can also use `*` as a wildcard _and_ use semver: `* > uglify-js@2.x`.
 *
 * The matchPath will break the `path` down into it's component parts, and loop through trying to
 * get a positive match or not. For full examples of options (see http://git.io/vCH3N)
 *
 * @param from the array of dependency paths from which a given vulnerability was introduced
 * @param path the rule path to match against
 * @returns whether the rule `path` matches a dependency path in the vulnerability's `from` array
 */
function matchPath(from: string[], path: string) {
  const parts = path.split(' > ');
  debugPolicy('checking path: %s vs. %s', path, from);
  let offset = 0;

  const res = parts.every((pkg, i) => {
    debugPolicy('for %s...(against %s)', pkg, from[i + offset]);
    let fromPkg = from[i + offset]
      ? moduleToObject(from[i + offset])
      : ({} as Package);

    if (pkg === '*') {
      debugPolicy('star rule');

      // handle the rule being `*` alone
      if (!parts[i + 1]) {
        return true;
      }

      const next = moduleToObject(parts[i + 1]);

      // assuming we're not at the end of the rule path, then try to find
      // the next matching package in the chain. So `* > semver` matches
      // `foo > bar > semver`
      if (next) {
        debugPolicy('next', next);
        // move forward until we find a matching package
        for (let j = i; i < parts.length; j++) {
          // if we've run out of paths, then we didn't match
          if (!from[i + offset]) {
            return false;
          }
          fromPkg = moduleToObject(from[i + offset]);
          debugPolicy('fromPkg', fromPkg, next);

          if (next.name === fromPkg.name) {
            // adjust for the `i` index incrementing in the next .every call
            offset--;
            debugPolicy('next has a match');
            break;
          }
          debugPolicy('pushing offset');
          offset++;
        }
      }

      return true;
    }

    debugPolicy('next test', pkg, fromPkg);

    if (pkg === from[i + offset]) {
      debugPolicy('exact match');
      return true;
    }

    const target = moduleToObject(pkg);

    let pkgVersion = target.version;

    // the * semver rule won't match pre-releases, which in our case is a
    // problem, so if the version is indeed *, we'll reset it to the exact same
    // version as our target package to allow for a match.
    if (pkgVersion === '*') {
      pkgVersion = fromPkg.version;
    }

    // shortcut version match, if it's exact, then skip the semver check
    if (target.name === fromPkg.name) {
      if (fromPkg.version === pkgVersion) {
        debugPolicy('exact version match');
        return true;
      }

      if (
        semver.valid(fromPkg.version) &&
        semver.satisfies(fromPkg.version, pkgVersion)
      ) {
        debugPolicy('semver match');
        return true;
      }
    }

    debugPolicy('failed match');

    return false;
  });
  debugPolicy('result of path test %s: %s', path, res);
  return res;
}

/**
 * Returns whether any of the rule paths match the path in which the vulnerability was introduced.
 * @param vuln a single vulnerability, where `from` contains the dependency path in which it was introduced
 * @param rule an ignore rule for the given vulnerability with one or more paths to ignore
 * @param matchStrategy the strategy used to match vulnerabilities (defaults to 'packageManager')
 * @returns whether any ignore rules match the vulnerabilities import path
 */
function matchToRule(
  vuln: Vulnerability,
  pathObj: PathObj,
  matchStrategy: MatchStrategy = 'packageManager'
) {
  return Object.keys(pathObj).some((path) =>
    matchToSingleRule(vuln, path, matchStrategy)
  );
}

/**
 * Returns whether a single rule path matches the path in which the vulnerability was introduced.
 * @param vuln a single vulnerability, where `from` contains the dependency path in which it was introduced
 * @param path the rule path to match against
 * @param matchStrategy the strategy used to match vulnerabilities (defaults to 'packageManager')
 * @returns whether the rule `path` matches a dependency path in the `from` array
 */
function matchToSingleRule(
  vuln: Vulnerability,
  path: string,
  matchStrategy: MatchStrategy
) {
  if (matchStrategy === 'exact') {
    return matchExactWithStars(vuln, path);
  }

  // check for an exact match
  let pathMatch = false;
  const from = vuln.from.slice(1);
  if (path.indexOf(from.join(' > ')) !== -1) {
    debug('%s exact match from %s', vuln.id, from);
    pathMatch = true;
  } else if (matchPath(from, path)) {
    pathMatch = true;
  }

  return pathMatch;
}

function matchExactWithStars(vuln: Vulnerability, path: string) {
  const parts = path.split(' > ');
  if (parts[parts.length - 1] === '*') {
    const paddingLength = vuln.from.length - parts.length;
    for (let i = 0; i < paddingLength; i++) {
      parts.push('*');
    }
  }
  if (parts.length !== vuln.from.length) {
    return false;
  }
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] !== vuln.from[i] && parts[i] !== '*') {
      return false;
    }
  }
  return true;
}

/**
 * Returns any matching rule given a specific vulnerability object. The `vuln` object must contain
 * `id` and `from` to match correctly.
 * @param policy the policy object to apply to the vulnerabilities
 * @param vuln a single vulnerability, where `from` contains the dependency path in which it was introduced
 * @returns the matching rule, or null if no match was found
 */
function getByVuln(policy?: Policy, vuln?: Vulnerability): VulnRule | null {
  let found: VulnRule | null = null;

  if (!policy || !vuln) {
    return found;
  }

  for (const key of ['ignore', 'patch'] as ('ignore' | 'patch')[]) {
    Object.keys(policy[key] || []).forEach((p) => {
      if (p === vuln.id) {
        for (const rule of policy[key][p]) {
          if (matchToRule(vuln, rule)) {
            const rootRule = Object.keys(rule).pop()!; // eslint-disable-line @typescript-eslint/no-non-null-assertion
            found = {
              type: key,
              id: vuln.id,
              rule: vuln.from,
              ...rule[rootRule],
            } as VulnRule;
          }
        }
      }
    });
  }

  return found;
}
