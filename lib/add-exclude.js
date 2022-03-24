module.exports = addExclude;

function addExclude(policy, pattern, group = 'global', options = {}) {
  if (!isPatternGroupValid(group)) {
    throw new Error('invalid file pattern-group');
  }

  policy.exclude = policy.exclude || {};

  let patterns = policy.exclude[group] || [];

  // Remove duplicates
  patterns = patterns.filter((p) => p !== pattern && !p[pattern]);

  options.created = new Date();

  const entry =
    !options.expires && !options.reason ? pattern : { [pattern]: options };

  policy.exclude[group] = [...patterns, entry];
}

function isPatternGroupValid(group) {
  return ['global', 'code', 'iac-drift'].includes(group);
}
