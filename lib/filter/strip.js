module.exports = stripFiltered;

function stripFiltered(vulns) {
  var filtered = vulns.vulnerabilities.filter(function (vuln) {
    return !vuln.filtered;
  });

  return {
    vulnerabilities: filtered,
    ok: vulns.ok || filtered.length === 0,
  };
}
