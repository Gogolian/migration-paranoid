'use strict';

const rules = [
  {
    id: 'SQL001',
    description: 'SET NOT NULL on existing column',
    linePattern: /SET\s+NOT\s+NULL/i,
    risks: [
      'May scan full table.',
      'May fail if existing rows contain NULL.',
      'Unsafe during rolling deploy unless app already writes email.',
    ],
  },
  {
    id: 'SQL002',
    description: 'ADD COLUMN NOT NULL without DEFAULT',
    linePattern: /ADD\s+COLUMN/i,
    matchFn(line, window) {
      return /ADD\s+COLUMN/i.test(line) &&
             /NOT\s+NULL/i.test(window) &&
             !/DEFAULT/i.test(window);
    },
    risks: [
      'Locks table on most databases.',
      'Fails if existing rows have no value for this column.',
    ],
  },
  {
    id: 'SQL003',
    description: 'CREATE INDEX without CONCURRENTLY',
    linePattern: /CREATE\s+INDEX/i,
    matchFn(line, window) {
      return /CREATE\s+INDEX/i.test(line) && !/CREATE\s+INDEX\s+CONCURRENTLY/i.test(line);
    },
    risks: [
      'Locks table reads and writes during index build.',
      'Use CREATE INDEX CONCURRENTLY to avoid locking (PostgreSQL).',
    ],
  },
  {
    id: 'SQL004',
    description: 'DROP TABLE',
    linePattern: /DROP\s+TABLE/i,
    risks: [
      'Irreversible data loss.',
      'Cannot be undone without a backup.',
    ],
  },
  {
    id: 'SQL005',
    description: 'DROP COLUMN',
    linePattern: /DROP\s+COLUMN/i,
    risks: [
      'Irreversible data loss.',
      'Table lock while column is removed.',
    ],
  },
  {
    id: 'SQL006',
    description: 'TRUNCATE TABLE',
    linePattern: /\bTRUNCATE\b/i,
    risks: [
      'Irreversible data loss.',
      'Removes all rows without logging individual deletes.',
    ],
  },
  {
    id: 'SQL007',
    description: 'DELETE without WHERE',
    linePattern: /DELETE\s+FROM/i,
    matchFn(line, window) {
      return /DELETE\s+FROM/i.test(line) && !/WHERE/i.test(window);
    },
    risks: [
      'May delete all rows in the table.',
      'Add a WHERE clause to limit scope.',
    ],
  },
  {
    id: 'SQL008',
    description: 'RENAME TABLE or COLUMN',
    linePattern: /RENAME\s+(TABLE|COLUMN|TO)\b/i,
    risks: [
      'Breaks rolling deploys — old app code references old name.',
      'Coordinate rename with application code deploy.',
    ],
  },
  {
    id: 'SQL009',
    description: 'ALTER COLUMN TYPE',
    linePattern: /(ALTER\s+COLUMN\s+\w+\s+TYPE|MODIFY\s+COLUMN)/i,
    risks: [
      'May require full table rewrite.',
      'Table lock during type conversion.',
    ],
  },
  {
    id: 'SQL010',
    description: 'ADD UNIQUE CONSTRAINT or CREATE UNIQUE INDEX',
    linePattern: /(ADD\s+CONSTRAINT\s+\w+\s+UNIQUE|CREATE\s+UNIQUE\s+INDEX)/i,
    risks: [
      'Scans full table to validate uniqueness.',
      'Fails if duplicate values exist.',
    ],
  },
  {
    id: 'SQL011',
    description: 'DROP DATABASE',
    linePattern: /DROP\s+DATABASE/i,
    risks: [
      'Catastrophic and irreversible data loss.',
      'Destroys entire database.',
    ],
  },
  {
    id: 'SQL012',
    description: 'ADD FOREIGN KEY constraint',
    linePattern: /REFERENCES\s+\w+/i,
    risks: [
      'May lock parent table during constraint validation.',
      'Consider adding index before constraint.',
    ],
  },
];

module.exports = rules;
