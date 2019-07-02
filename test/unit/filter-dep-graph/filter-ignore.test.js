var test = require('tap').test;
var depGraphLib = require('@snyk/dep-graph');
var policy = require('../../../');
var path = require('path');
var fixtures = path.join(__dirname, '../../fixtures/filter-dep-graph/ignore');

var vulns = require(path.join(fixtures, 'vulns.json'));
var depGraph = require(path.join(fixtures, 'dep-graph.json'));
// var ignore = require('../../lib/filter/ignore');

test('ignored vulns do not turn up in tests', (t) => {
  return policy.load(fixtures)
    .then((config) => {
      const result = config.filter({
        ok: false,
        vulnerabilities: vulns,
        dependencyGraph: depGraphLib.createFromJSON(depGraph),
      });

      console.log(result);
    });


  // vulnsToReturn = policy.filter({
  //   ok: vulnsToReturn.length === 0,
  //   vulnerabilities: vulnsToReturn,
  // }).vulnerabilities;
  // return Promise.reject(new Error());
  // t.end();
// return Promise.reject('aaaa');

//   policy.load(fixtures).then(function (config) {
//     var start = vulns.vulnerabilities.length;
//     t.ok(vulns.vulnerabilities.length > 0, 'we have vulns to start with');
//
//     var filtered = [];
//
//     vulns.vulnerabilities = ignore(
//       config.ignore,
//       vulns.vulnerabilities,
//       filtered
//     );
//
//     // should strip 4
//     t.equal(start - 4, vulns.vulnerabilities.length, 'post filter: ' + vulns.vulnerabilities.length);
//     t.equal(4, filtered.length, '4 vulns filtered');
//     var expected = {
//       'npm:hawk:20160119': [
//         {
//           reason: 'hawk got bumped',
//           expires: '2116-03-01T14:30:04.136Z',
//           path: ['sqlite', 'sqlite3', 'node-pre-gyp', 'request', 'hawk'],
//         },
//       ],
//       'npm:is-my-json-valid:20160118': [
//         {
//           reason: 'dev tool',
//           expires: '2116-03-01T14:30:04.136Z',
//           path: [
//             'sqlite', 'sqlite3', 'node-pre-gyp', 'request', 'har-validator',
//             'is-my-json-valid',
//           ],
//         },
//       ],
//       'npm:tar:20151103': [
//         {
//           reason: 'none given',
//           expires: '2116-03-01T14:30:04.137Z',
//           path: ['sqlite', 'sqlite3', 'node-pre-gyp', 'tar-pack', 'tar'],
//         },
//       ],
//       'npm:marked:20170907': [
//         {
//           reason: 'none given',
//           disregardIfFixable: true,
//           path: ['*'],
//         },
//       ],
//     };
//     var actual = filtered.reduce(
//       function (actual, vuln) {
//         actual[vuln.id] = vuln.filtered.ignored;
//         return actual;
//       },
//       {});
//     t.same(actual, expected, 'filtered vulns include ignore rules');
//
//     t.notEqual(vulns.vulnerabilities.every(function (vuln) {
//       return !!vuln.ignored;
//     }), 'vulns do not have ignored property');
// }).catch(t.threw).then(t.end);
});
