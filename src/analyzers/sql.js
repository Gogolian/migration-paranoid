'use strict';
const rules = require('../rules/sql-rules');

function analyze(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  for (const rule of rules) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!rule.linePattern.test(line)) continue;

      // Build a statement window: current line + up to 7 following lines
      const windowEnd = Math.min(lines.length, i + 8);
      const statementWindow = lines.slice(i, windowEnd).join(' ');

      const matched = rule.matchFn
        ? rule.matchFn(line, statementWindow)
        : true;

      if (matched) {
        findings.push({
          ruleId: rule.id,
          description: rule.description,
          line: line.trim(),
          lineNumber: i + 1,
          snippet: line.trim(),
          risks: rule.risks,
        });
      }
    }
  }

  return findings;
}

module.exports = { analyze };
