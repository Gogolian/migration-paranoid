'use strict';
const fs = require('fs');
const path = require('path');

function scanDirectory(dir) {
  const results = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (e) {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const type = detectType(fullPath, entry.name);
        if (type) {
          results.push({ filePath: fullPath, type });
        }
      }
    }
  }

  walk(dir);
  return results;
}

function detectType(filePath, fileName) {
  const ext = path.extname(fileName).toLowerCase();
  const base = path.basename(fileName).toLowerCase();

  if (ext === '.py') {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      if (/class\s+Migration/i.test(content)) {
        return 'django';
      }
    } catch (e) {}
    return null;
  }

  if (ext === '.rb') {
    if (/^\d+_/.test(base)) {
      return 'rails';
    }
    const dirPath = path.dirname(filePath).toLowerCase();
    if (dirPath.includes('migration')) {
      return 'rails';
    }
    return null;
  }

  if (ext === '.sql') {
    if (base === 'migration.sql') {
      return 'prisma';
    }
    return 'sql';
  }

  if (ext === '.xml' || ext === '.yaml' || ext === '.yml') {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      if (/changeSet/i.test(content)) {
        return 'liquibase';
      }
    } catch (e) {}
    return null;
  }

  return null;
}

module.exports = { scanDirectory, detectType };
