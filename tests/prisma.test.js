'use strict';
const { analyze } = require('../src/analyzers/prisma');

describe('Prisma analyzer', () => {
  test('reuses SQL rules - DROP TABLE flags as risky', () => {
    const content = 'DROP TABLE "User";';
    const findings = analyze('migration.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL004')).toBe(true);
  });

  test('reuses SQL rules - CREATE INDEX without CONCURRENTLY flags as risky', () => {
    const content = 'CREATE INDEX "idx_user_email" ON "User"("email");';
    const findings = analyze('migration.sql', content);
    expect(findings.some(f => f.ruleId === 'SQL003')).toBe(true);
  });

  test('clean Prisma migration returns empty findings', () => {
    const content = `
CREATE TABLE "User" (
    "id" SERIAL PRIMARY KEY,
    "name" TEXT NOT NULL
);`;
    const findings = analyze('migration.sql', content);
    expect(findings).toHaveLength(0);
  });
});
