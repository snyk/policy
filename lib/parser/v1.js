// eventually we'll have v2 which will point to latestParser, and v1 will
// need to process the old form of data and upgrade it to v2 structure
module.exports = function imports(policy) {
  if (!policy.ignore) {
    policy.ignore = {};
  }

  if (!policy.patch) {
    policy.patch = {};
  }

  checkForOldFormat(policy.ignore);
  validate(policy.ignore);
  validate(policy.ignore);

  return policy;
};

module.exports.needsFixing = needsFixing;

function checkForOldFormat(ignore) {
  // this is a cursory test to ensure that we're working with a snyk format
  // that we recognise. if the property is an object, then it's the early
  // alpha format, and we'll throw
  Object.keys(ignore).forEach(function (id) {
    if (!Array.isArray(ignore[id])) {
      var error = new Error('old, unsupported .snyk format detected');
      error.code = 'OLD_DOTFILE_FORMAT';
      throw error;
    }
  });
}

function validate(policy) {
  var fix = needsFixing(policy);

  if (fix) {
    fix.forEach(function (item) {
      var o = {};
      o[item.key] = item.rule;
      policy[item.id].push(o);
    });
  }
}

function needsFixing(policy) {
  var move = [];
  Object.keys(policy).forEach(function (id) {
    policy[id].forEach(function (rule) {
      var keys = Object.keys(rule);
      keys.shift(); // drop the first

      if (keys === 0) {
        return;
      }

      // this means our policy has become corrupted, and we need to move
      // the additional keys into their own position in the policy
      keys.forEach(function (key) {
        move.push({
          id: id,
          key: key,
          rule: rule[key],
        });
        delete rule[key];
      });
    });
  });

  return move.length ? move : false;
}
