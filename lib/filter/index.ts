export default filter;

import newDebug from 'debug';

import {
  MatchStrategy,
  Policy,
  Rule,
  Vulnerability,
  VulnsObject,
} from '../types';
import ignore from './ignore';
import notes from './notes';
import patch from './patch';

const debug = newDebug('snyk:policy');

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

/**
 * Applies the specified policy to the vulnerabilities object.
 * @param vulns (*mutates!*) the vulnerabilities object to filter
 * @param policy the policy object to apply to the vulnerabilities
 * @param root the root directory to use for patching (defaults to process.cwd())
 * @param matchStrategy the strategy used to match vulnerabilities (defaults to 'packageManager')
 * @returns the filtered vulnerabilities object
 */
function filter(
  vulns: VulnsObject,
  policy: Policy,
  root: string,
  matchStrategy: MatchStrategy = 'packageManager'
) {
  if (!root) {
    root = process.cwd();
  }

  if (vulns.ok) {
    return vulns as FilteredVulns;
  }

  const filtered = {
    ignore: [] as FilteredVulnerability[],
    patch: [] as FilteredVulnerability[],
  };

  // converts vulns to filtered vulns
  const filteredVulns = vulns as FilteredVulns;

  // strip the ignored modules from the results
  filteredVulns.vulnerabilities = ignore(
    policy.ignore,
    filteredVulns.vulnerabilities,
    filtered.ignore,
    matchStrategy
  );

  filteredVulns.vulnerabilities = patch(
    policy.patch,
    filteredVulns.vulnerabilities,
    root,
    policy.skipVerifyPatch ? true : false,
    filtered.patch
  );

  if (policy.suggest) {
    filteredVulns.vulnerabilities = notes(
      policy.suggest,
      filteredVulns.vulnerabilities
    );
  }

  // if there's no vulns after the ignore process, let's reset the `ok`
  // state and remove the vulns entirely.
  if (filteredVulns.vulnerabilities.length === 0) {
    filteredVulns.ok = true;
    filteredVulns.vulnerabilities = [];
  }

  filteredVulns.filtered = filtered;

  debug('> has threshold? %s', policy.failThreshold);

  if (policy.failThreshold && vulns.ok === false) {
    // check what's left and switch the failure flag if there's anything
    // under our threshold
    const levels = {
      high: 3,
      medium: 2,
      low: 1,
    };
    const level = levels[policy.failThreshold];
    filteredVulns.ok = true;
    filteredVulns.vulnerabilities.some((vuln) => {
      if (levels[vuln.severity] >= level) {
        filteredVulns.ok = false;
        return true; // breaks
      }

      return false;
    });
  }

  return filteredVulns;
}
