import * as fs from 'then-fs';
import * as path from 'path';
import * as debugModule from 'debug';
import * as parse from './parser';
import * as tryRequire from 'snyk-try-require';
import { add } from './add';
import { filter } from './filter';
import { demunge } from './parser/demunge';
import { LoadedPolicy, MethodsPolicy, Policy } from './types';

export { add } from './add';
export { filter } from './filter';
export { demunge } from './parser/demunge';
export { getByVuln, matchToRule } from './match';

const debug = debugModule('snyk:policy');

export async function create(): Promise<MethodsPolicy> {
  return loadFromText('');
}

// this is a function to allow our tests and fixtures to change cwd
function defaultFilename(): string {
  return path.resolve(process.cwd(), '.snyk');
}

function attachMethods(loaded: LoadedPolicy): MethodsPolicy {
  const policy = loaded as MethodsPolicy;
  policy.filter = (vulns, root) =>
    filter(vulns, policy, root || path.dirname(policy.__filename));
  policy.save = save.bind(null, policy);
  policy.toString = parse.exportsOf.bind(null, policy);
  policy.demunge = demunge.bind(null, policy);
  policy.add = add.bind(null, policy);
  policy.addIgnore = add.bind(null, policy, 'ignore');
  policy.addPatch = add.bind(null, policy, 'patch');
  return policy;
}

export async function loadFromText(text: string): Promise<MethodsPolicy> {
  return new Promise(function(resolve) {
    const policy = parse.imports(text);
    const now = Date.now();

    const loaded: LoadedPolicy = {
      ...policy,
      __filename: '',
      __modified: now,
      __created: now,
    };

    resolve(loaded);
  }).then(attachMethods);
}

export async function load(root?: string, options?): Promise<MethodsPolicy> {
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

  const promise = new Promise(function(resolve) {
    if (ignorePolicy) {
      return resolve(parse.imports());
    }

    if (!ignorePolicy && Array.isArray(root)) {
      return resolve(
        mergePolicies(root, options).then(function(res) {
          debug('final policy:');
          debug(JSON.stringify(res, undefined, 2));
          return res;
        }),
      );
    }

    resolve(fs.readFile(filename, 'utf8').then(parse.imports));
  });

  const promises = [
    promise,
    fs.stat(filename).catch(function() {
      return {};
    }),
  ];

  return Promise.all(promises)
    .catch(function(error) {
      if (options.loose && error.code === 'ENOENT') {
        debug('ENOENT on file, but running loose');
        return [parse.imports(), {}];
      }

      throw error;
    })
    .then(function(res) {
      const policy: LoadedPolicy = res[0];

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

async function mergePolicies(policyDirs, options) {
  const ignoreTarget = options['trust-policies'] ? 'ignore' : 'suggest';

  return Promise.all(
    policyDirs.map(async (dir) => {
      return load(dir, options);
    }),
  ).then(async (policies) => {
    // firstly extend the paths in the ignore and patch
    const rootPolicy = policies[0];
    const others = policies.slice(1);

    return Promise.all(
      others
        .filter(function(policy: any) {
          return policy.__filename; // filter out non loaded policies
        })
        .map(function(policy: any) {
          const filename = path.dirname(policy.__filename) + '/package.json';

          return tryRequire(filename).then(function(pkg) {
            const full = pkg.name + '@' + pkg.version;

            mergePath('ignore', ignoreTarget, full, rootPolicy, policy);
            mergePath('patch', 'patch', full, rootPolicy, policy);
          });
        }),
    ).then(function() {
      return rootPolicy;
    });
  });
}

// note: mutates both objects, be warned!
function mergePath(type, into, pathRoot, rootPolicy, policy) {
  if (!rootPolicy[into]) {
    rootPolicy[into] = {};
  }

  Object.keys(policy[type]).forEach(function(id) {
    // convert the path from `module@version` to `parent > module@version`
    policy[type][id] = policy[type][id].map(function(path) {
      // this is because our policy file format favours "readable" yaml,
      // instead of easy to use object structures.
      const key = Object.keys(path).pop();
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

export async function save<T>(
  object: Policy,
  root?: string,
  spinner?: any,
): Promise<unknown> {
  const filename = root ? path.resolve(root, '.snyk') : defaultFilename();

  const lbl = 'Saving .snyk policy file...';

  if (!spinner) {
    spinner = async (res: unknown): Promise<unknown> => {
      return Promise.resolve(res);
    };
    spinner.clear = spinner;
  }

  return spinner(lbl)
    .then(function() {
      return parse.exportsOf(object);
    })
    .then(function(yaml) {
      return fs.writeFile(filename, yaml);
    })
    .then(spinner.clear(lbl));
}

/* istanbul ignore if */
if (!module.parent) {
  load(process.argv[2])
    .then(function(res) {
      console.log(JSON.stringify(res, undefined, 2));
    })
    .catch(function(e) {
      console.log(e.stack);
    });
}
