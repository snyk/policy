module.exports = filter;

var ignore = require('./ignore');
var patch = require('./patch');
var notes = require('./notes');

// warning: mutates vulns
function filter(vulns, policy, root) {
  if (!root) {
    root = process.cwd();
  }

  if (vulns.ok) {
    return vulns;
  }

  // strip the ignored modules from the results
  vulns.vulnerabilities = ignore(
    policy.ignore,
    vulns.vulnerabilities,
    root
  );

  vulns.vulnerabilities = patch(
    policy.patch,
    vulns.vulnerabilities,
    root,
    policy.skipVerifyPatch ? true : false
  );

  if (policy.suggest) {
    vulns.vulnerabilities = notes(
      policy.suggest,
      vulns.vulnerabilities,
      root
    );
  }

  // if there's no vulns after the ignore process, let's reset the `ok`
  // state and remove the vulns entirely.
  if (vulns.vulnerabilities.length === 0) {
    vulns.ok = true;
    delete vulns.vulnerabilities;
  }

  return vulns;
}