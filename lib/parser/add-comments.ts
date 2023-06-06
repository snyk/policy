export default addComments;

const initialComment =
  '# Snyk (https://snyk.io) policy file, patches or ' +
  'ignores known vulnerabilities.';
const inlineComments = {
  ignore:
    '# ignores vulnerabilities until expiry date; change duration by ' +
    'modifying expiry date',
  patch: '# patches apply the minimum changes required to fix a vulnerability',
};

/**
 * Adds comments to the exported policy file.
 * @param policyExport policy file as a string
 * @returns the policy file with comments
 */
function addComments(policyExport: string) {
  const lines = policyExport.split('\n');
  lines.unshift(initialComment);

  for (const key in inlineComments) {
    const position = lines.indexOf(key + ':');
    if (position !== -1) {
      lines.splice(position, 0, inlineComments[key]);
    }
  }

  return lines.join('\n');
}
