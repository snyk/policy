import newDebug from 'debug';
import { lstatSync, promises as fs, Stats } from 'fs';
import * as path from 'path';
import tryRequire from 'snyk-try-require';
import add from './add';
import addExclude from './add-exclude';
import filter from './filter';
import * as parse from './parser';
import { MatchStrategy, Policy } from './types';

export { demunge } from './parser';
export { getByVuln, matchToRule } from './match';
export { filter, load, save, loadFromText, add, addExclude, create };

const debug = newDebug('snyk:policy');

/** Returns the version of the latest policy schema */
export const latestVersion = () => 'v1.25.1'; // only major _should_ matter, but deferring for now

function create() {
  return loadFromText('');
}

// this is a function to allow our tests and fixtures to change cwd
function defaultFilename() {
  return path.resolve(process.cwd(), '.snyk');
}

function attachMethods(policy) {
  policy.filter = (
    vulns,
    root,
    matchStrategy: MatchStrategy = 'packageManager'
  ) =>
    filter(
      vulns,
      policy,
      root || path.dirname(policy.__filename),
      matchStrategy
    );

  policy.save = (root, spinner) => save(policy, root, spinner);
  policy.toString = () => parse.export(policy);
  policy.demunge = (apiRoot) => parse.demunge(policy, apiRoot);
  policy.add = (type, options) => add(policy, type, options);
  policy.addIgnore = (options) => add(policy, 'ignore', options);
  policy.addPatch = (options) => add(policy, 'patch', options);
  policy.addExclude = (pattern, group, options) =>
    addExclude(policy, pattern, group, options);
  return policy;
}

function loadFromText(text) {
  return new Promise(function (resolve) {
    const policy = parse.import(text);
    const now = Date.now();

    policy.__filename = '';
    policy.__modified = now;
    policy.__created = now;

    resolve(policy);
  }).then(attachMethods);
}

function load(root?, options?) {
  if (!Array.isArray(root) && typeof root !== 'string') {
    options = root;
    root = null;
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
    if (error.code === 'ENOENT') {
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
      if (options.loose && error.code === 'ENOENT') {
        debug('ENOENT on file, but running loose');
        return [parse.import(), {} as Stats] as [Policy, Stats];
      }

      throw error;
    })
    .then((res) => {
      const policy = res[0] as Policy;

      policy.__modified = res[1].mtime;
      policy.__created = res[1].birthtime || res[1].ctime;

      if (options.loose && !policy.__modified) {
        policy.__filename = null;
      } else {
        policy.__filename = path.relative(process.cwd(), filename);
      }

      return policy;
    })
    .then(attachMethods);
}

function mergePolicies(policyDirs, options) {
  const ignoreTarget = options['trust-policies'] ? 'ignore' : 'suggest';

  return Promise.all(
    policyDirs.map(function (dir) {
      return load(dir, options);
    })
  ).then(function (policies) {
    // firstly extend the paths in the ignore and patch
    const rootPolicy = policies[0];
    const others = policies.slice(1);

    return Promise.all(
      others
        .filter(function (policy) {
          return policy.__filename; // filter out non loaded policies
        })
        .map(function (policy) {
          const filename = path.dirname(policy.__filename) + '/package.json';

          return tryRequire(filename).then(function (pkg) {
            const full = pkg.name + '@' + pkg.version;

            mergePath('ignore', ignoreTarget, full, rootPolicy, policy);
            mergePath('patch', 'patch', full, rootPolicy, policy);
          });
        })
    ).then(function () {
      return rootPolicy;
    });
  });
}

// note: mutates both objects, be warned!
function mergePath(type, into, pathRoot, rootPolicy, policy) {
  if (!rootPolicy[into]) {
    rootPolicy[into] = {};
  }

  Object.keys(policy[type]).forEach((id) => {
    // convert the path from `module@version` to `parent > module@version`
    policy[type][id] = policy[type][id].map((path) => {
      // this is because our policy file format favours "readable" yaml,
      // instead of easy to use object structures.
      const key = Object.keys(path).pop()!;
      const newPath = {};
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

function save(object, root, spinner?) {
  const filename = root ? path.resolve(root, '.snyk') : defaultFilename();

  const lbl = 'Saving .snyk policy file...';

  if (!spinner) {
    spinner = function (res) {
      return Promise.resolve(res);
    };
    spinner.clear = spinner;
  }

  return spinner(lbl)
    .then(function () {
      return parse.export(object);
    })
    .then(function (yaml) {
      return fs.writeFile(filename, yaml);
    })
    .then(spinner.clear(lbl));
}
