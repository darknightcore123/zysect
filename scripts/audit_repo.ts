import fs from 'fs';
import path from 'path';
import { runScan } from '../src/scanner/index.js'; // Adjust if using compiled dist

const targetDir = process.argv[2];

if (!targetDir) {
  console.error('❌ Please provide a target directory. Example: npx tsx scripts/audit_repo.ts ../zysect_test_repos/kiwimu-mbti');
  process.exit(1);
}

let totalFilesScanned = 0;
let totalFindings = 0;
const report: Record<string, any[]> = {};

function scanDirectory(dirPath: string) {
  const files = fs.readdirSync(dirPath);

  for (const file of files) {
    const fullPath = path.join(dirPath, file);
    const stat = fs.statSync(fullPath);

    // Skip heavy build folders and hidden directories
    if (stat.isDirectory() && !file.startsWith('.') && file !== 'node_modules') {
      scanDirectory(fullPath);
    } else if (stat.isFile() && /\.(ts|js|tsx|jsx|py)$/.test(file)) {
      totalFilesScanned++;
      const content = fs.readFileSync(fullPath, 'utf-8');
      
      const result = runScan({ filePath: fullPath, fileContent: content });
      
      if (result.findings.length > 0) {
        report[fullPath] = result.findings;
        totalFindings += result.findings.length;
        console.log(`\n🚨 FOUND ${result.findings.length} ISSUE(S) IN: ${fullPath}`);
        result.findings.forEach(f => {
            console.log(`   [${f.severity}] ${f.rule} (Confidence: ${f.confidence}%)`);
            console.log(`   Line ${f.line}: ${f.message}`);
        });
      }
    }
  }
}

console.log(`\n🔍 Starting Zysect Bulk Audit on: ${targetDir}`);
const startTime = Date.now();
scanDirectory(path.resolve(targetDir));
const duration = Date.now() - startTime;

console.log('\n=======================================');
console.log('📊 AUDIT COMPLETE');
console.log(`⏱️  Time: ${duration}ms`);
console.log(`📄 Files Scanned: ${totalFilesScanned}`);
console.log(`🚩 Total Findings: ${totalFindings}`);
console.log('=======================================\n');