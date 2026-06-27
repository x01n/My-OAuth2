const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DIST = path.resolve(ROOT, '../server/web/dist');
const OUT = path.resolve(ROOT, 'out');

const BASELINE_BROWSER_MAPPING_WARNING =
  '[baseline-browser-mapping] The data in this module is over two months old.';

function run(args) {
  const executable = process.platform === 'win32' ? 'bun.exe' : 'bun';
  const result = spawnSync(executable, args, {
    cwd: ROOT,
    env: process.env,
    shell: false,
    encoding: 'utf8',
  });

  writeFilteredOutput(process.stdout, result.stdout);
  writeFilteredOutput(process.stderr, result.stderr);

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

function writeFilteredOutput(stream, output) {
  if (!output) {
    return;
  }
  for (const line of output.split(/\r?\n/)) {
    if (!line) {
      continue;
    }
    if (line.includes(BASELINE_BROWSER_MAPPING_WARNING)) {
      continue;
    }
    stream.write(`${line}\n`);
  }
}

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}
fs.rmSync(DIST, { recursive: true, force: true });
fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(DIST, { recursive: true });
fs.writeFileSync(path.join(DIST, 'placeholder.txt'), 'placeholder\n');
run(['run', 'typecheck']);
run(['x', 'next', 'build', '--webpack']);
if (fs.existsSync(OUT)) {
  copyDir(OUT, DIST);
  console.log('[build] 完成!');
} else {
  console.error('[build] 错误: out 目录不存在，请确认 next.config 已配置 output: "export"');
  process.exit(1);
}
