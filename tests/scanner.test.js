'use strict';
const path = require('path');
const fs = require('fs');
const os = require('os');
const { scanDirectory } = require('../src/scanner');

describe('Scanner', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'migration-paranoid-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('finds .sql files', () => {
    fs.writeFileSync(path.join(tmpDir, '001_create_users.sql'), 'CREATE TABLE users (id INT);');
    const files = scanDirectory(tmpDir);
    expect(files.some(f => f.type === 'sql')).toBe(true);
  });

  test('finds Rails .rb migration files', () => {
    fs.writeFileSync(path.join(tmpDir, '20240101120000_create_users.rb'), "def change\n  create_table :users\nend");
    const files = scanDirectory(tmpDir);
    expect(files.some(f => f.type === 'rails')).toBe(true);
  });

  test('finds Django .py migration files', () => {
    fs.writeFileSync(path.join(tmpDir, '0001_initial.py'), 'class Migration(migrations.Migration):\n  pass');
    const files = scanDirectory(tmpDir);
    expect(files.some(f => f.type === 'django')).toBe(true);
  });

  test('ignores non-migration Python files', () => {
    fs.writeFileSync(path.join(tmpDir, 'utils.py'), 'def helper(): pass');
    const files = scanDirectory(tmpDir);
    expect(files.some(f => f.type === 'django')).toBe(false);
  });

  test('returns empty array for empty directory', () => {
    const files = scanDirectory(tmpDir);
    expect(files).toHaveLength(0);
  });

  test('recursively finds files in subdirectories', () => {
    const subDir = path.join(tmpDir, 'db', 'migrations');
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(subDir, '001_create.sql'), 'CREATE TABLE t (id INT);');
    const files = scanDirectory(tmpDir);
    expect(files.length).toBeGreaterThan(0);
  });
});
