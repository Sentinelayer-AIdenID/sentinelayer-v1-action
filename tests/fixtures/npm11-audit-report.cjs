// Offline npm report fixture: never fetch advisories or execute package code.
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const deny = () => { throw new Error('npm report fixture forbids network and child processes'); };
require('node:net').Socket.prototype.connect = deny;
require('node:tls').connect = deny;
require('node:dns').lookup = deny;
global.fetch = deny;
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  require('node:child_process')[name] = deny;
}

const npmRoot = path.resolve(process.argv[2]);
const project = path.resolve(process.argv[3]);
const npmVersion = require(path.join(npmRoot, 'package.json')).version;
if (npmVersion !== '11.11.0') throw new Error(`Expected npm 11.11.0, found ${npmVersion}`);
const Arborist = require(path.join(npmRoot, 'node_modules/@npmcli/arborist'));
const reportPath = path.join(npmRoot, 'node_modules/@npmcli/arborist/lib/audit-report.js');
const AuditReport = require(reportPath);

(async () => {
  const tree = await new Arborist({path: project, offline: true, ignoreScripts: true}).loadVirtual();
  const report = new AuditReport(tree, {offline: true, omit: []});
  const bulk = report.prepareBulkData();
  const nodes = [...tree.inventory.values()].filter(node => !node.isRoot);
  const missing = nodes.filter(node => !(bulk[node.packageName] || []).includes(node.version));
  if (missing.length) throw new Error('Audit payload omitted installed nodes');
  const optionalEdges = [...tree.inventory.values()].flatMap(node => [...node.edgesOut.values()])
    .filter(edge => edge.name === 'optional-peer')
    .map(edge => ({from: edge.from.location, to: edge.to?.location, type: edge.type, valid: edge.valid}));
  process.stdout.write(JSON.stringify({
    npm_version: npmVersion,
    report_source_sha256: crypto.createHash('sha256').update(fs.readFileSync(reportPath)).digest('hex'),
    inventory_count: nodes.length,
    bulk_name_count: Object.keys(bulk).length,
    optional_peer_edges: optionalEdges,
    report: report.toJSON(),
  }, null, 2) + '\n');
})().catch(error => { console.error(error); process.exitCode = 1; });
