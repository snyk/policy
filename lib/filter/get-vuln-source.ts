// FIXME move to ext module

export default getVulnSource;

import newDebug from 'debug';
import { statSync } from 'fs';
import * as path from 'path';

import { parsePackageString as moduleToObject } from 'snyk-module';
import resolve from 'snyk-resolve';

import { Vulnerability } from '../types';

const debug = newDebug('snyk:policy');
// eslint-disable-next-line no-console
debug.log = console.error.bind(console);

/**
 * Get the path to the vulnerable dependency's source
 * @param vuln the vulnerability
 * @param cwd the current working directory
 * @param live set to true to throw if source is not found
 * @returns the local path to the dependency
 */
function getVulnSource(vuln: Vulnerability, cwd: string, live: boolean) {
  const from = vuln.from.slice(1).map((pkg) => moduleToObject(pkg).name);

  const viaPath = path.resolve(
    cwd || process.cwd(),
    'node_modules',
    from.join('/node_modules/'),
  );

  let source = vuln.__filename ? path.dirname(vuln.__filename) : viaPath;

  // try to stat the directory, if it throws, it doesn't exist...
  try {
    statSync(source);
  } catch (e) {
    // ...which means the package is located in a parent path (from an
    // npm dedupe process), so we remove the module name from the path
    // and use the `resolve` package to navigate the node_modules up
    // through parent directories.
    try {
      source = resolve.sync(from.slice(-1)?.pop(), viaPath);
    } catch (e) {
      if (live) {
        throw e;
      }

      // otherwise this is a dry run so we don't mind that it won't be
      // able to patch - likely a scenario run, so it's fine that the
      // patch target won't be found
    }
    debug('found better source for package: %s', source);
  }

  return source;
}
