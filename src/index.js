'use strict';
const { scanDirectory } = require('./scanner');
const { analyze: analyzeSql } = require('./analyzers/sql');
const { analyze: analyzeRails } = require('./analyzers/rails');
const { analyze: analyzeDjango } = require('./analyzers/django');
const { analyze: analyzePrisma } = require('./analyzers/prisma');
const { report } = require('./reporter');
const fs = require('fs');

async function run(dir) {
  const files = scanDirectory(dir);

  if (files.length === 0) {
    console.log('No migration files found.');
    return 0;
  }

  const allFindings = [];

  for (const { filePath, type } of files) {
    const content = fs.readFileSync(filePath, 'utf8');
    let findings = [];

    if (type === 'sql' || type === 'flyway') {
      findings = analyzeSql(filePath, content);
    } else if (type === 'rails') {
      findings = analyzeRails(filePath, content);
    } else if (type === 'django') {
      findings = analyzeDjango(filePath, content);
    } else if (type === 'prisma') {
      findings = analyzePrisma(filePath, content);
    }

    if (findings.length > 0) {
      allFindings.push({ filePath, findings });
    }
  }

  report(allFindings, files.length);
  return allFindings.length > 0 ? 1 : 0;
}

module.exports = { run };
