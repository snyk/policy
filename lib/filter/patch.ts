export default filterPatched;

import newDebug from 'debug';
import { statSync, Stats } from 'fs';
import cloneDeep from 'lodash.clonedeep';
import * as path from 'path';

import { matchToRule } from '../match';
import {
  FilteredRule,
  FilteredVulnerability,
  RuleSet,
  Vulnerability,
} from '../types';
import getVulnSource from './get-vuln-source';

const debug = newDebug('snyk:policy');

/**
 * Given a patched rule set (parsed from the `.snyk` yaml file) and a array of vulnerabilities,
 * return the vulnerabilities that *are not* patched.
 * @param patched the patched rule set
 * @param vulns the currently present vulnerabilities
 * @param cwd used for testing
 * @param skipVerifyPatch set to true to skip verifying that the patch file exists. The rule will be ignored if it does not.
 * @param filteredPatches (**mutates!**) an optional out parameter to collect vulnerabilities that have been ignored
 * @returns the remaining un-patched vulnerabilities
 */
function filterPatched<T extends Vulnerability>(
  patched: RuleSet,
  vulns: T[],
  cwd: string,
  skipVerifyPatch: boolean,
  filteredPatches: T[] = []
) {
  if (!patched) {
    return vulns as FilteredVulnerability<T>[];
  }

  debug('filtering patched');
  return (
    vulns
      // forcing vuln to be a filteredVulnerability to get around the fact that we're mutating the
      // vuln object in place - we should refactor this to be more functional
      .map((vuln: FilteredVulnerability<T>) => {
        if (!patched[vuln.id]) {
          return vuln;
        }

        debug('%s has rules', vuln.id);

        // logic: loop through all rules (from `patched[vuln.id]`), and if *any* dep
        // paths match our vuln.from dep chain AND a flag exists, then the
        // vulnerability is ignored. if none of the rules match, then let we'll
        // keep it.

        // if rules.find, then ignore vuln
        const vulnRules = patched[vuln.id]
          .map((rule) => {
            // first check if the path is a match on the rule
            const pathMatch = matchToRule(vuln, rule);

            if (pathMatch) {
              const path = Object.keys(rule)[0]; // this is a string
              debug(
                '(patch) ignoring based on path match: %s ~= %s',
                path,
                vuln.from.slice(1).join(' > ')
              );
              return rule;
            }

            return null;
          })
          .filter(isNotNull);

        // run through the potential rules to check if there's a patch flag in place
        const appliedRules = vulnRules.filter(() => {
          // the target directory where our module name will live
          if (skipVerifyPatch) {
            return true;
          }

          const source = getVulnSource(vuln, cwd, true);

          const id = vuln.id.replace(/:/g, '-');
          const flag = path.resolve(source, '.snyk-' + id + '.flag');
          const oldFlag = path.resolve(source, '.snyk-' + vuln.id + '.flag');
          let res: Stats | false = false;
          try {
            res = statSync(flag);
          } catch (e) {
            try {
              res = statSync(oldFlag);
            } catch (e) {
              // continue regardless of error
            }
          }

          debug('flag found for %s? %s', vuln.id);

          return !!res;
        });

        if (appliedRules.length) {
          vuln.filtered = {
            patches: appliedRules.map((rule) => {
              const path = Object.keys(rule)[0];
              const ruleData = (cloneDeep(rule[path]) || {}) as FilteredRule;
              ruleData.path = path.split(' > ');
              return ruleData;
            }),
          };
          filteredPatches.push(vuln);
        }

        return appliedRules.length ? null : vuln;
      })
      .filter(isNotNull)
  );
}

const isNotNull = <T>(v: T): v is NonNullable<T> => v !== null;
