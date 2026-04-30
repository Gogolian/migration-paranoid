'use strict';
const { analyze } = require('../src/analyzers/rails');

describe('Rails analyzer', () => {
  test('RB001: add_column null: false without default flags as risky', () => {
    const content = "add_column :users, :email, :string, null: false";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB001')).toBe(true);
  });

  test('RB001: add_column null: false with default is clean', () => {
    const content = "add_column :users, :email, :string, null: false, default: ''";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB001')).toBe(false);
  });

  test('RB002: change_column flags as risky', () => {
    const content = "change_column :users, :email, :text";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB002')).toBe(true);
  });

  test('RB003: remove_column flags as risky', () => {
    const content = "remove_column :users, :email";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB003')).toBe(true);
  });

  test('RB004: drop_table flags as risky', () => {
    const content = "drop_table :users";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB004')).toBe(true);
  });

  test('RB005: rename_column flags as risky', () => {
    const content = "rename_column :users, :email, :email_address";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB005')).toBe(true);
  });

  test('RB006: rename_table flags as risky', () => {
    const content = "rename_table :users, :accounts";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB006')).toBe(true);
  });

  test('RB007: add_index without algorithm: :concurrently flags as risky', () => {
    const content = "add_index :users, :email";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB007')).toBe(true);
  });

  test('RB007: add_index with algorithm: :concurrently is clean', () => {
    const content = "add_index :users, :email, algorithm: :concurrently";
    const findings = analyze('migration.rb', content);
    expect(findings.some(f => f.ruleId === 'RB007')).toBe(false);
  });

  test('clean migration returns empty findings', () => {
    const content = `
      def change
        create_table :users do |t|
          t.string :name
          t.timestamps
        end
      end
    `;
    const findings = analyze('migration.rb', content);
    expect(findings).toHaveLength(0);
  });
});
