import { ExcludeRuleSet, PatternGroup, Policy, Rule } from './types';

export default addExclude;

type AddExcludeOptions = Rule;

/**
 * Adds an exclude rule to the policy.
 * @param policy (*mutates!*) the policy object to add the rule to
 * @param pattern the pattern to exclude
 * @param group the pattern group to add the pattern to
 * @param options the options for the rule
 */
function addExclude(
  policy: Policy,
  pattern: string,
  group: PatternGroup = 'global',
  options = {} as AddExcludeOptions
) {
  if (!isPatternGroupValid(group)) {
    throw new Error('invalid file pattern-group');
  }

  policy.exclude = policy.exclude ?? ({} as ExcludeRuleSet);

  let patterns = policy.exclude[group] ?? [];

  // Remove duplicates
  patterns = patterns.filter((p) => p !== pattern && !p[pattern]);

  options.created = new Date();

  const entry =
    !options.expires && !options.reason ? pattern : { [pattern]: options };

  policy.exclude[group] = [...patterns, entry];
}

function isPatternGroupValid(group: string) {
  return ['global', 'code', 'iac-drift'].includes(group);
}
