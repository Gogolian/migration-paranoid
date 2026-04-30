'use strict';

const rules = [
  {
    id: 'DJ001',
    description: 'AddField with null=False and no default',
    linePattern: /AddField/,
    matchFn(line, window) {
      return /AddField/.test(line) &&
             /null\s*=\s*False/.test(window) &&
             !/\bdefault\b/.test(window);
    },
    risks: [
      'Locks table on large datasets.',
      'Fails on existing rows without a default.',
    ],
  },
  {
    id: 'DJ002',
    description: 'RemoveField',
    linePattern: /RemoveField/,
    risks: [
      'Irreversible data loss.',
      'Table lock while column is removed.',
    ],
  },
  {
    id: 'DJ003',
    description: 'DeleteModel',
    linePattern: /DeleteModel/,
    risks: [
      'Irreversible data loss — drops entire table.',
    ],
  },
  {
    id: 'DJ004',
    description: 'RenameField',
    linePattern: /RenameField/,
    risks: [
      'Breaks rolling deploy — old app code uses old field name.',
    ],
  },
  {
    id: 'DJ005',
    description: 'RenameModel',
    linePattern: /RenameModel/,
    risks: [
      'Breaks rolling deploy — old app code references old model name.',
    ],
  },
  {
    id: 'DJ006',
    description: 'AlterField',
    linePattern: /AlterField/,
    risks: [
      'May require full table rewrite.',
      'Existing data may not be compatible.',
    ],
  },
  {
    id: 'DJ007',
    description: 'AddConstraint with UniqueConstraint',
    linePattern: /AddConstraint/,
    matchFn(line, window) {
      return /AddConstraint/.test(line) && /UniqueConstraint/.test(window);
    },
    risks: [
      'Scans full table to validate uniqueness.',
      'Fails if duplicate values exist.',
    ],
  },
];

module.exports = rules;
