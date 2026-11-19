'use strict';
// Lists upstream sources for binding.gyp, without the files that src/ replaces.
const fs = require('node:fs');
const path = require('node:path');

const dir = path.join(__dirname, '..', 'src', 'masscan', 'src');
const skip = new Set(['main.c', 'output.c', 'util-logger.c', 'main-status.c']);

if (!fs.existsSync(dir)) {
  console.error('src/masscan is empty. Run: git submodule update --init');
  process.exit(1);
}

for (const file of fs.readdirSync(dir).sort()) {
  if (file.endsWith('.c') && !skip.has(file)) {
    console.log(path.posix.join('src', 'masscan', 'src', file));
  }
}
