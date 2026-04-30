# migration-paranoid

A static analyzer for risky database migrations. Detects dangerous patterns across SQL, Rails, Django, and Prisma migration files before they cause production incidents.

## Installation

```bash
npm install -g migration-paranoid
```

## Usage

```bash
migration-paranoid <directory>
```

Example:

```bash
migration-paranoid ./db/migrations
```

## Supported Migration Formats

| Format | File Detection |
|--------|---------------|
| Plain SQL | `*.sql` |
| Rails | `*.rb` migration files (timestamp-prefixed or in migrations dir) |
| Django | `*.py` files containing `class Migration` |
| Prisma | `migration.sql` |
| Liquibase | `*.xml`, `*.yaml`, `*.yml` files containing `changeSet` |

## Rules

### SQL Rules

| Rule | Description |
|------|-------------|
| SQL001 | SET NOT NULL on existing column |
| SQL002 | ADD COLUMN NOT NULL without DEFAULT |
| SQL003 | CREATE INDEX without CONCURRENTLY |
| SQL004 | DROP TABLE |
| SQL005 | DROP COLUMN |
| SQL006 | TRUNCATE TABLE |
| SQL007 | DELETE without WHERE clause |
| SQL008 | RENAME TABLE or COLUMN |
| SQL009 | ALTER COLUMN TYPE |
| SQL010 | ADD UNIQUE CONSTRAINT |
| SQL011 | DROP DATABASE |
| SQL012 | ADD FOREIGN KEY |

### Rails Rules

| Rule | Description |
|------|-------------|
| RB001 | add_column with null: false and no default |
| RB002 | change_column |
| RB003 | remove_column |
| RB004 | drop_table |
| RB005 | rename_column |
| RB006 | rename_table |
| RB007 | add_index without algorithm: :concurrently |
| RB008 | add_reference without explicit index: false |

### Django Rules

| Rule | Description |
|------|-------------|
| DJ001 | AddField with null=False and no default |
| DJ002 | RemoveField |
| DJ003 | DeleteModel |
| DJ004 | RenameField |
| DJ005 | RenameModel |
| DJ006 | AlterField |
| DJ007 | AddConstraint with UniqueConstraint |

## Exit Codes

- `0` — No risky migrations found
- `1` — One or more risky patterns detected

## License

MIT