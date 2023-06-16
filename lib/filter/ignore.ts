export default filterIgnored;

import newDebug from 'debug';
import cloneDeep from 'lodash.clonedeep';

import { matchToRule } from '../match';
import {
  FilteredRule,
  FilteredVulnerability,
  MatchStrategy,
  MetaRule,
  PathObj,
  RuleSet,
  Vulnerability,
} from '../types';

const debug = newDebug('snyk:policy');

/**
 * Given an ignore rule set (parsed from the `.snyk` yaml file) and a array of vulnerabilities,
 * return the vulnerabilities that *are not* ignored. See http://git.io/vCHmV for example of what
 * ignore structure looks like.
 * @param ignore the ignore rule set
 * @param vulns the currently present vulnerabilities
 * @param filtered (**mutates!**) an optional out parameter to collect vulnerabilities that have been ignored
 * @param matchStrategy the strategy used to match vulnerabilities
 * @returns the remaining un-ignored vulnerabilities
 */
function filterIgnored<T extends Vulnerability>(
  ignore: RuleSet,
  vulns: T[],
  filtered: T[] = [],
  matchStrategy: MatchStrategy = 'packageManager'
) {
  if (!ignore) {
    return vulns as FilteredVulnerability<T>[];
  }

  debug('filtering ignored');
  const now = new Date().toJSON();

  return (
    vulns
      // forcing vuln to be a filteredVulnerability to get around the fact that we're mutating the
      // vuln object in place - we should refactor this to be more functional
      .map((vuln: FilteredVulnerability<T>) => {
        const applySecurityPolicyIgnore = vulnHasSecurityPolicyIgnore(vuln);
        if (!ignore[vuln.id] && !applySecurityPolicyIgnore) {
          return vuln;
        }

        debug('%s has rules', vuln.id);

        let appliedRules: PathObj[] = [];

        if (applySecurityPolicyIgnore) {
          // logic: if vuln has securityPolicyMetaData.ignore rule, that means it comes
          // after security rule applied with the ignore action, thus we have to apply
          // this ignore and not any others.
          // Security policies ignores we apply to all paths "*" and disregardIfFixable=false
          const rule = vuln.securityPolicyMetaData.ignore;

          const {
            created,
            disregardIfFixable,
            ignoredBy,
            path,
            reason = '',
            reasonType,
            source,
          } = rule;

          appliedRules = [
            {
              [path[0] as string]: {
                reason,
                reasonType,
                source,
                ignoredBy,
                created,
                disregardIfFixable,
              },
            },
          ];
        } else {
          // logic: loop through all rules (from `ignore[vuln.id]`), and if *any* dep
          // paths match our vuln.from dep chain AND the rule hasn't expired, then the
          // vulnerability is ignored. if none of the rules match, then let we'll
          // keep it.

          // if rules.find, then ignore vuln
          appliedRules = ignore[vuln.id].filter((rule) => {
            const path = Object.keys(rule)[0];
            let expires = rule[path].expires;

            if (expires && expires instanceof Date) {
              expires = expires.toJSON();
            }

            // first check if the path is a match on the rule
            const pathMatch = matchToRule(vuln, rule, matchStrategy);

            if (pathMatch && expires && expires < now) {
              debug('%s vuln rule has expired (%s)', vuln.id, expires);
              return false;
            }

            if (
              pathMatch &&
              rule[path].disregardIfFixable &&
              (vuln.isUpgradable || vuln.isPatchable)
            ) {
              debug(
                '%s vuln is fixable and rule is set to disregard if fixable',
                vuln.id
              );
              return false;
            }

            if (pathMatch) {
              if (debug.enabled) {
                debug(
                  'ignoring based on path match: %s ~= %s',
                  path,
                  vuln.from.slice(1).join(' > ')
                );
              }
              return true;
            }

            return false;
          });
        }

        if (appliedRules.length) {
          vuln.filtered = {
            ignored: appliedRules.map((rule) => {
              const path = Object.keys(rule)[0];
              const ruleData = cloneDeep(rule[path]) as FilteredRule;
              ruleData.path = path.split(' > ');
              return ruleData;
            }),
          };
          filtered.push(vuln);
        }

        return appliedRules.length ? null : vuln;
      })
      .filter(isNotNull)
  );
}

const vulnHasSecurityPolicyIgnore = (vuln: Vulnerability): vuln is Vulnerability & { securityPolicyMetaData: { ignore: MetaRule } } =>
  !!(vuln.securityPolicyMetaData && vuln.securityPolicyMetaData.ignore);

const isNotNull = <T>(v: T): v is NonNullable<T> => v !== null;
