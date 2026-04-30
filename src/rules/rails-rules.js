'use strict';

const rules = [
  {
    id: 'RB001',
    description: 'add_column with null: false and no default',
    linePattern: /\badd_column\b/i,
    matchFn(line, window) {
      return /\badd_column\b/i.test(line) &&
             /null:\s*false/i.test(window) &&
             !/default:/i.test(window);
    },
    risks: [
      'Locks table on large datasets.',
      'Fails on existing rows without a default value.',
    ],
  },
  {
    id: 'RB002',
    description: 'change_column',
    linePattern: /\bchange_column\b/i,
    risks: [
      'May lock table during type change.',
      'Existing data may not be compatible with new type.',
    ],
  },
  {
    id: 'RB003',
    description: 'remove_column',
    linePattern: /\bremove_column\b/i,
    risks: [
      'Irreversible data loss.',
      'Table lock while column is removed.',
    ],
  },
  {
    id: 'RB004',
    description: 'drop_table',
    linePattern: /\bdrop_table\b/i,
    risks: [
      'Irreversible data loss.',
    ],
  },
  {
    id: 'RB005',
    description: 'rename_column',
    linePattern: /\brename_column\b/i,
    risks: [
      'Breaks rolling deploy — old app code uses old column name.',
    ],
  },
  {
    id: 'RB006',
    description: 'rename_table',
    linePattern: /\brename_table\b/i,
    risks: [
      'Breaks rolling deploy — old app code uses old table name.',
    ],
  },
  {
    id: 'RB007',
    description: 'add_index without algorithm: :concurrently',
    linePattern: /\badd_index\b/i,
    matchFn(line, window) {
      return /\badd_index\b/i.test(line) &&
             !/algorithm:\s*:concurrently/i.test(window);
    },
    risks: [
      'Locks table during index build.',
      'Use algorithm: :concurrently to avoid locking.',
    ],
  },
  {
    id: 'RB008',
    description: 'add_reference without explicit index: false',
    linePattern: /\b(add_reference|add_belongs_to)\b/i,
    risks: [
      'May lock table while adding foreign key or index.',
    ],
  },
];

module.exports = rules;
