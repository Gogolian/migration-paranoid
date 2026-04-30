'use strict';

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function report(findings, totalFiles) {
  if (findings.length === 0) {
    console.log(`${GREEN}✅ No risky migrations found in ${totalFiles} files${RESET}`);
    return;
  }

  for (const { filePath, findings: fileFindings } of findings) {
    const fileName = require('path').basename(filePath);
    console.log(`\n${RED}🚨 ${BOLD}${fileName}${RESET}`);
    console.log();

    for (const finding of fileFindings) {
      console.log(`  ${DIM}${finding.snippet}${RESET}`);
      console.log();
      console.log(`  ${YELLOW}Risk:${RESET}`);
      for (const risk of finding.risks) {
        console.log(`  - ${risk}`);
      }
      console.log();
    }
  }

  const totalIssues = findings.reduce((sum, f) => sum + f.findings.length, 0);
  console.log('──────────────────────────────────────────');
  console.log(`  ${RED}${totalIssues} issue${totalIssues !== 1 ? 's' : ''} found in ${totalFiles} migration file${totalFiles !== 1 ? 's' : ''}${RESET}`);
  console.log('  Run with --help for more information');
}

module.exports = { report };
