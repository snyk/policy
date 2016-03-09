module.exports = {
  import: imports,
  export: exports,
  demunge: require('./demunge'),
};

var version = module.exports.version = 'v1';
var cloneDeep = require('lodash.clonedeep');
var yaml = require('js-yaml');

var parsers = {
  v1: require('./v1'),
};

function imports(rawYaml) {
  var data = yaml.safeLoad(rawYaml || '');

  if (!data) {
    data = {};
  }

  if (!data.version) {
    data.version = version;
  }

  if (!parsers[data.version]) {
    throw new Error('unsupported version: ' + data.version);
  }

  return parsers[data.version](data);
}

function exports(policy) {
  var data = cloneDeep(policy);

  // remove any private information on the policy
  Object.keys(data).map(function (key) {
    if (key.indexOf('__') === 0) {
      delete data[key];
    }

    // strip helper functions
    if (typeof data[key] === 'function') {
      delete data[key];
    }
  });

  // ensure we always update the version of the policy format
  data.version = version;

  return yaml.safeDump(data);
}