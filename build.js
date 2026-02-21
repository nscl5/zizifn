import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { build } from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function runBuild() {
  console.log("🐾 Starting build process...");

  const result = await build({
    entryPoints: [join(__dirname, './index.js')],
    bundle: true,
    format: 'esm',
    target: 'esnext',
    external: ['cloudflare:sockets'],
    minify: true,
    write: false
  });

  mkdirSync(join(__dirname, 'dist'), { recursive: true });
  const outputPath = join(__dirname, 'dist/worker.js');
  
  const finalCode = `// Time is: ${new Date().toISOString()}\n${result.outputFiles[0].text}`;
  
  writeFileSync(outputPath, finalCode, 'utf8');
  console.log("🧸 Build successful! Final worker file is located in the root directory with the name _worker.js");
}

runBuild().catch(() => process.exit(1));
