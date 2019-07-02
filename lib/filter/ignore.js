module.exports = ignore;

const cloneDeep = require('lodash.clonedeep');
const debug = require('debug')('snyk:policy');
const matchToRule = require('../match').matchToRule;

/**
 * @param rules
 * @param vuln
 * @param vuln.id
 * @param vuln.from
 * @param vuln.isUpgradable
 * @param vuln.isPatchable
 * @return {Array}
 */
function getApplicableRules(rules, vuln) {
  const now = (new Date()).toJSON();

  if (!rules[vuln.id]) {
    return [];
  }

  debug('%s has rules', vuln.id);

  return rules[vuln.id].filter((rule) => {
    const path = Object.keys(rule)[0]; // this is a string
    const disregardIfFixable = !!rule[path].disregardIfFixable;
    let expires = rule[path].expires;

    if (expires && expires.toJSON) {
      expires = expires.toJSON();
    }

    const pathMatch = matchToRule(vuln, rule);

    if (pathMatch) {
      if (disregardIfFixable && (vuln.isUpgradable || vuln.isPatchable)) {
        debug('%s vuln is fixable and rule is set to disregard if fixable', vuln.id);
      } else if (expires && expires < now) {
        debug('%s vuln rule has expired (%s)', vuln.id, expires);
      } else {
        debug('ignoring based on path match: %s ~= %s', path, vuln.from.slice(1).join(' > '));
        return true;
      }
    }

    return false;
  });
}

function formatRulesToIgnored(rules) {
  return rules.map((rule) => {
    const path = Object.keys(rule)[0];
    const ruleData = cloneDeep(rule[path]);
    ruleData.path = path.split(' > ');
    return ruleData;
  });
}

function ignoreTree(ignore, vulns, filtered) {
  const notIgnoredVulns = [];

  for (const vuln of vulns.vulnerabilities) {
    const rules = getApplicableRules(ignore, vuln);

    if (rules.length > 0) {
      vuln.filtered = {
        ignored: formatRulesToIgnored(rules),
      };
      filtered.push(vuln);
    } else {
      notIgnoredVulns.push(vuln);
    }
  }

  vulns.vulnerabilities = notIgnoredVulns;
}

function ignoreGraph(ignore, vulns, filtered) {
  const appliedRules = new Map();

  for (const packageData of Object.values(vulns.vulnerabilities.affectedPkgs)) {
    for (const issue of Object.values(packageData.issues)) {
      const paths = vulns.dependencyGraph.pkgPathsToRoot(packageData.pkg);
      const isPatchable = issue.fixInfo.isPatchable;
      const isUpgradable = issue.fixInfo.upgradePaths.length > 0; // TODO: check specific path
      const id = issue.issueId;

      let ignoredPaths = 0;

      for (const from of paths) {
        const rules = getApplicableRules(ignore, {
          id,
          isPatchable,
          isUpgradable,
          from: from.reverse().map((p) => `${p.name}@${p.version}`),
        });

        if (rules.length > 0) {
          ignoredPaths++;
          if (appliedRules.has(id)) {
            appliedRules.set(id, [...appliedRules.get(id), ...formatRulesToIgnored(rules)]);
          } else {
            appliedRules.set(id, formatRulesToIgnored(rules));
          }
        }
      }

      if (ignoredPaths === paths.length) {
        delete packageData.issues[id];
      }
    }
  }

  for (const vuln of Object.values(vulns.vulnerabilities.issuesData)) {
    if (appliedRules.has(vuln.id)) {
      vuln.filtered = {
        ignored: appliedRules.get(vuln.id),
      };
    }
  }
}

function ignore(ignore, vulns, filtered = []) {
  if (!ignore && Object.keys(ignore).length === 0) {
    return;
  }

  debug('filtering ignored');

  if (vulns.dependencyGraph) {
    ignoreGraph(ignore, vulns, filtered);
  } else {
    ignoreTree(ignore, vulns, filtered);
  }
}
