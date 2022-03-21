module.exports = addExclude;

function addExclude(policy, pattern, group='global') {
  if (!isPatternGroupValid(group)) {
    throw new Error('invalid file pattern-group');
  }

  policy.exclude = policy.exclude ? policy.exclude: {};

  const patterns = policy.exclude[group] ? policy.exclude[group]: [];

  if (patterns.includes(pattern)) {
    return; // Exit early, to prevent duplication
  }

  policy.exclude[group] = [...patterns, pattern];
}

function isPatternGroupValid(group) {
  return ['global', 'code'].includes(group);
}
