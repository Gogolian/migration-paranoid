'use strict';
const { analyze } = require('../src/analyzers/sql');

describe('SQL analyzer', () => {
  test('SQL001: SET NOT NULL flags as risky', () => {
    const content = 'ALTER TABLE users ALTER COLUMN email SET NOT NULL;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL001')).toBe(true);
  });

  test('SQL002: ADD COLUMN NOT NULL without DEFAULT flags as risky', () => {
    const content = 'ALTER TABLE users ADD COLUMN status TEXT NOT NULL;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL002')).toBe(true);
  });

  test('SQL002: ADD COLUMN NOT NULL with DEFAULT is clean', () => {
    const content = "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';";
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL002')).toBe(false);
  });

  test('SQL003: CREATE INDEX without CONCURRENTLY flags as risky', () => {
    const content = 'CREATE INDEX idx_users_email ON users(email);';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL003')).toBe(true);
  });

  test('SQL003: CREATE INDEX CONCURRENTLY is clean', () => {
    const content = 'CREATE INDEX CONCURRENTLY idx_users_email ON users(email);';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL003')).toBe(false);
  });

  test('SQL004: DROP TABLE flags as risky', () => {
    const content = 'DROP TABLE users;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL004')).toBe(true);
  });

  test('SQL005: DROP COLUMN flags as risky', () => {
    const content = 'ALTER TABLE users DROP COLUMN email;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL005')).toBe(true);
  });

  test('SQL006: TRUNCATE flags as risky', () => {
    const content = 'TRUNCATE TABLE users;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL006')).toBe(true);
  });

  test('SQL007: DELETE FROM without WHERE flags as risky', () => {
    const content = 'DELETE FROM users;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL007')).toBe(true);
  });

  test('SQL007: DELETE FROM with WHERE is clean', () => {
    const content = 'DELETE FROM users WHERE id = 1;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL007')).toBe(false);
  });

  test('SQL008: RENAME COLUMN flags as risky', () => {
    const content = 'ALTER TABLE users RENAME COLUMN email TO email_address;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL008')).toBe(true);
  });

  test('SQL009: ALTER COLUMN TYPE flags as risky', () => {
    const content = 'ALTER TABLE users ALTER COLUMN age TYPE integer;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL009')).toBe(true);
  });

  test('SQL010: ADD CONSTRAINT UNIQUE flags as risky', () => {
    const content = 'ALTER TABLE users ADD CONSTRAINT unique_email UNIQUE (email);';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL010')).toBe(true);
  });

  test('SQL011: DROP DATABASE flags as risky', () => {
    const content = 'DROP DATABASE myapp;';
    const findings = analyze('test.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL011')).toBe(true);
  });

  test('clean migration returns empty findings', () => {
    const content = 'CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT);';
    const findings = analyze('test.sql', content);
    expect(findings).toHaveLength(0);
  });
});
