'use strict';
const { analyze: analyzeSql } = require('./sql');

function analyze(filePath, content) {
  return analyzeSql(filePath, content);
}

module.exports = { analyze };
