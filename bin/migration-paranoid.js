#!/usr/bin/env node
'use strict';

const path = require('path');
const { run } = require('../src/index');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: migration-paranoid <directory>');
  process.exit(1);
}

const dir = path.resolve(args[0]);
run(dir).then(exitCode => process.exit(exitCode));
