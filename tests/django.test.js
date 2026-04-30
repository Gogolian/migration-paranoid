'use strict';
const { analyze } = require('../src/analyzers/django');

describe('Django analyzer', () => {
  test('DJ001: AddField with null=False and no default flags as risky', () => {
    const content = `
migrations.AddField(
    model_name='user',
    name='email',
    field=models.CharField(max_length=255, null=False),
),`;
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ001')).toBe(true);
  });

  test('DJ001: AddField with null=False and default is clean', () => {
    const content = `
migrations.AddField(
    model_name='user',
    name='email',
    field=models.CharField(max_length=255, null=False, default=''),
),`;
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ001')).toBe(false);
  });

  test('DJ002: RemoveField flags as risky', () => {
    const content = "migrations.RemoveField(model_name='user', name='email'),";
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ002')).toBe(true);
  });

  test('DJ003: DeleteModel flags as risky', () => {
    const content = "migrations.DeleteModel(name='User'),";
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ003')).toBe(true);
  });

  test('DJ004: RenameField flags as risky', () => {
    const content = "migrations.RenameField(model_name='user', old_name='email', new_name='email_address'),";
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ004')).toBe(true);
  });

  test('DJ005: RenameModel flags as risky', () => {
    const content = "migrations.RenameModel(old_name='User', new_name='Account'),";
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ005')).toBe(true);
  });

  test('DJ006: AlterField flags as risky', () => {
    const content = "migrations.AlterField(model_name='user', name='email', field=models.TextField()),";
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ006')).toBe(true);
  });

  test('DJ007: AddConstraint with UniqueConstraint flags as risky', () => {
    const content = `
migrations.AddConstraint(
    model_name='user',
    constraint=models.UniqueConstraint(fields=['email'], name='unique_email'),
),`;
    const findings = analyze('0001_migration.py', content);
    expect(findings.some(f => f.ruleId === 'DJ007')).toBe(true);
  });

  test('clean migration returns empty findings', () => {
    const content = `
from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = []
    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(primary_key=True)),
                ('name', models.CharField(max_length=100)),
            ],
        ),
    ]
`;
    const findings = analyze('0001_migration.py', content);
    expect(findings).toHaveLength(0);
  });
});
