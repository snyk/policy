export default filter;

// import newDebug from 'debug';

import {
  FilteredVulnerability,
  FilteredVulnerabilityReport,
  MatchStrategy,
  Policy,
  Vulnerability,
  VulnerabilityReport,
} from '../types';
import ignore from './ignore';
import notes from './notes';
import patch from './patch';

// const debug = newDebug('snyk:policy');

/**
 * Applies the specified policy to the vulnerabilities object.
 * @param vulns (*mutates!*) the vulnerabilities object to filter
 * @param policy the policy object to apply to the vulnerabilities
 * @param root the root directory to use for patching (defaults to process.cwd())
 * @param matchStrategy the strategy used to match vulnerabilities (defaults to 'packageManager')
 * @returns the filtered vulnerabilities object
 */
function filter<VulnType extends Vulnerability, ReportType>(
  vulns: ReportType & VulnerabilityReport<VulnType>,
  policy: Policy,
  root?: string,
  matchStrategy: MatchStrategy = 'packageManager',
) {
  if (!root) {
    root = process.cwd();
  }

  // converts vulns to filtered vulns
  const filteredVulns = vulns as ReportType &
    FilteredVulnerabilityReport<VulnType>;

  if (vulns.ok) {
    return filteredVulns;
  }

  const filtered = {
    ignore: [] as FilteredVulnerability<VulnType>[],
    patch: [] as FilteredVulnerability<VulnType>[],
  };

  // strip the ignored modules from the results
  filteredVulns.vulnerabilities = ignore(
    policy.ignore,
    filteredVulns.vulnerabilities,
    filtered.ignore,
    matchStrategy,
  );

  filteredVulns.vulnerabilities = patch(
    policy.patch,
    filteredVulns.vulnerabilities,
    root,
    policy.skipVerifyPatch ? true : false,
    filtered.patch,
  );

  if (policy.suggest) {
    filteredVulns.vulnerabilities = notes(
      policy.suggest,
      filteredVulns.vulnerabilities,
    );
  }

  // if there's no vulns after the ignore process, let's reset the `ok`
  // state and remove the vulns entirely.
  if (filteredVulns.vulnerabilities.length === 0) {
    filteredVulns.ok = true;
    filteredVulns.vulnerabilities = [];
  }

  filteredVulns.filtered = filtered;

  // debug('> has threshold? %s', policy.failThreshold);

  if (policy.failThreshold && vulns.ok === false) {
    // check what's left and switch the failure flag if there's anything
    // under our threshold
    const levels = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };
    const level = levels[policy.failThreshold];
    filteredVulns.ok = true;
    filteredVulns.vulnerabilities.some((vuln) => {
      if (vuln.severity && levels[vuln.severity] >= level) {
        filteredVulns.ok = false;
        return true; // breaks
      }

      return false;
    });
  }

  return filteredVulns;
}
