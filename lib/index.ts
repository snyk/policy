import newDebug from 'debug';
import { lstatSync, promises as fs, Stats } from 'fs';
import * as path from 'path';

import tryRequire from 'snyk-try-require';

import add from './add';
import addExclude from './add-exclude';
import filter from './filter';
import * as parse from './parser';
import { PathObj, Policy, Spinner, isNodeError } from './types';

export { demunge } from './parser';
export { getByVuln, matchToRule } from './match';
export { filter, load, save, loadFromText, add, addExclude, create };

const debug = newDebug('snyk:policy');

/** Returns the version of the latest policy schema */
export const latestVersion = () => 'v1.25.1'; // only major _should_ matter, but deferring for now

/** Returns an empty policy */
const create = () => loadFromText('');

// this function allows our tests and fixtures to change cwd
function defaultFilename() {
  return path.resolve(process.cwd(), '.snyk');
}

function attachMethods(policy: Pick<Policy, '__filename'> & Partial<Policy>) {
  policy.filter =
    (vulns, root?, matchStrategy = 'packageManager') =>
      filter(
        vulns,
        policy as Policy,
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        root || path.dirname(policy.__filename!), // will throw if __filename is null
        matchStrategy
      );
  policy.save = (root, spinner) => save(policy as Policy, root, spinner);
  policy.toString = () => parse.export(policy as Policy);
  policy.demunge = (apiRoot) => parse.demunge(policy as Policy, apiRoot);
  policy.add = (type: 'ignore' | 'patch', options) =>
    add(policy as Policy, type, options);
  policy.addIgnore = (options) => add(policy as Policy, 'ignore', options);
  policy.addPatch = (options) => add(policy as Policy, 'patch', options);
  policy.addExclude = (pattern, group, options) =>
    addExclude(policy as Policy, pattern, group, options);

  return policy as Policy;
}

/**
 * Loads a policy from text
 * @param text the policy text
 * @returns the policy
 */
async function loadFromText(text = '') {
  const policy = await parse.import(text);
  const now = Date.now();

  policy.__filename = '';
  policy.__modified = now;
  policy.__created = now;

  return attachMethods(policy)
}

interface loadOptions {
  loose?: boolean;
  'ignore-policy'?: boolean;
  'trust-policies'?: boolean;
}

/**
 * Loads a policy from disk. If `root` is an array of strings, the policies will be merged together.
 * @param root the root directory to load the policy from (default is `process.cwd())`
 * @param options options for loading the policy or policies
 * @returns a single policy if `root` is a string, or a merged policy if `root` is an array of strings
 */
function load(
  root?: string | string[] | loadOptions,
  options?: loadOptions
): Promise<Policy> {
  if (!Array.isArray(root) && typeof root !== 'string') {
    // the first argument are the load options
    options = root;
    root = undefined as string | string[] | undefined;
  }

  if (!root) {
    root = process.cwd();
  }

  if (!options) {
    options = {};
  }

  const ignorePolicy = !!options['ignore-policy'];

  let filename = '';
  if (Array.isArray(root)) {
    // we do a bit of a dance to get the first item in the array, and
    // use it as our filename
    filename = root[0];
  } else {
    if (root.indexOf('.snyk') === -1) {
      root = path.resolve(root, '.snyk');
    }
    filename = root;
  }

  if (filename.indexOf('.snyk') === -1) {
    filename = path.resolve(filename, '.snyk');
  }
  // Check if filename is directory and resolve to correct file path
  try {
    if (lstatSync(filename).isDirectory()) {
      filename = path.join(filename, '/.snyk');
    }
  } catch (error) {
    if (isNodeError(error) && error.code === 'ENOENT') {
      // Ignore if EOENT
      debug('ENOENT on file, while checking if directory');
    } else {
      throw error;
    }
  }

  const promise = new Promise<Policy>((resolve) => {
    if (ignorePolicy) {
      return resolve(parse.import());
    }

    if (!ignorePolicy && Array.isArray(root)) {
      return resolve(
        mergePolicies(root, options).then((res) => {
          if (debug.enabled) {
            debug('final policy:');
            debug(JSON.stringify(res, null, 2));
          }
          return res;
        })
      );
    }

    resolve(fs.readFile(filename, 'utf8').then(parse.import));
  });

  const promises: [Promise<Policy>, Promise<Stats>] = [
    promise,
    fs.stat(filename).catch(() => ({} as Stats)),
  ];

  return Promise.all(promises)
    .catch((error) => {
      if (options?.loose && error.code === 'ENOENT') {
        debug('ENOENT on file, but running loose');
        return [parse.import(), {} as Stats] as [Policy, Stats];
      }

      throw error;
    })
    .then((res) => {
      const policy = res[0] as Policy;

      policy.__modified = res[1].mtime;
      policy.__created = res[1].birthtime || res[1].ctime;

      if (options?.loose && !policy.__modified) {
        policy.__filename = null;
      } else {
        policy.__filename = path.relative(process.cwd(), filename);
      }

      return policy;
    })
    .then(attachMethods);
}

/**
 * Merge multiple policies together, with the first policy in the array being the root policy.
 *
 * Note: only Javascript projects are supported
 * @param policyDirs the directories containing the policies to merge
 * @param options options for loading the policies
 * @returns the root policy with all the other policies merged into it
 */
async function mergePolicies(policyDirs: string[], options?: loadOptions) {
  const ignoreTarget =
    options && options['trust-policies'] ? 'ignore' : 'suggest';

  const [rootPolicy, ...others] = await Promise.all(
    policyDirs.map((dir) => load(dir, options))
  );

  await Promise.all(
    others
      .filter((policy) => policy.__filename) // filter out non loaded policies
      .map(async (policy) => {
        const filename = path.dirname(policy.__filename!) + '/package.json'; // eslint-disable-line @typescript-eslint/no-non-null-assertion
        const pkg = await tryRequire(filename);
        const full = pkg.name + '@' + pkg.version;

        mergePath('ignore', ignoreTarget, full, rootPolicy, policy);
        mergePath('patch', 'patch', full, rootPolicy, policy);
      })
  );

  return rootPolicy;
}

/**
 * Merges a ruleset into the root policy.
 * @param type the ruleset type to merge
 * @param into the destination into the policy to merge the ruleset into
 * @param pathRoot the dependency path of the project to be merged into the root policy
 * @param rootPolicy (*mutates!*) the root policy
 * @param policy (*mutates!*) the policy to be merged into the root policy
 */
function mergePath(
  type: 'ignore' | 'patch',
  into: 'patch' | 'ignore' | 'suggest',
  pathRoot: string,
  rootPolicy: Policy,
  policy: Policy
) {
  if (!rootPolicy[into]) {
    rootPolicy[into] = {};
  }

  Object.keys(policy[type]).forEach((id) => {
    // convert the path from `module@version` to `parent > module@version`
    policy[type][id] = policy[type][id].map((path) => {
      // this is because our policy file format favours "readable" yaml,
      // instead of easy to use object structures.
      const key = Object.keys(path).pop()!; // eslint-disable-line @typescript-eslint/no-non-null-assertion
      const newPath = {} as PathObj;
      newPath[pathRoot + ' > ' + key] = path[key];
      path[key] = path[key] || {};
      path[key].from = pathRoot;
      return newPath;
    });

    // add the rule if we don't have it in our policy already
    if (!rootPolicy[into][id]) {
      rootPolicy[into][id] = policy[type][id];
      return;
    }

    // otherwise we need to merge up manually
    rootPolicy[into][id] = rootPolicy[into][id].concat(policy[type][id]);
  });
}

/**
 * Saves a policy to disk.
 * @param object the policy to save
 * @param root the root directory to save the policy to (default is `process.cwd())`
 * @param spinner a progress indicator, as used in the [Snyk CLI](https://github.com/Snyk/snyk-internal/blob/0459a7b21709c6a1d3c5edeb61b4abf2103ffaf0/cli/commands/protect/wizard.js#L268)
 * @returns the result of `spinner.clear()`
 */
async function save(object: Policy, root?: string, spinner?: Spinner) {
  const filename = root ? path.resolve(root, '.snyk') : defaultFilename();

  const lbl = 'Saving .snyk policy file...';

  if (!spinner) {
    const s = (res: string) => Promise.resolve(res);
    s.clear = s;

    spinner = s;
  }

  await spinner(lbl);

  const yaml = await parse.export(object);
  await fs.writeFile(filename, yaml);

  return spinner.clear(lbl);
}
