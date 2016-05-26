module.exports = filter;

var debug = require('debug')('snyk:policy');
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
  var ignored = ignore(
    policy.ignore,
    vulns.vulnerabilities
  );

  var patched = patch(
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
  if (patched && ignored) {
    vulns.ok = true;
  }

  debug('> has threshold? %s', policy.failThreshold);

  if (policy.failThreshold && vulns.ok === false) {
    // check what's left and switch the failure flag if there's anything
    // under our threshold
    var levels = {
      high: 3,
      medium: 2,
      low: 1,
    };
    var level = levels[policy.failThreshold];
    vulns.ok = true;
    vulns.vulnerabilities.some(function (vuln) {
      if (vuln.filtered) { // filtered vulns don't count
        return false;
      }

      if (levels[vuln.severity] >= level) {
        vulns.ok = false;
        return true; // breaks
      }
    });
  }

  return vulns;
}
