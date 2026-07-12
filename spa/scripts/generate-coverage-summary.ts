import { readFileSync, existsSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';

interface CoverageSummary {
  total: {
    statements: { total: number; covered: number; pct: number };
    branches: { total: number; covered: number; pct: number };
    functions: { total: number; covered: number; pct: number };
    lines: { total: number; covered: number; pct: number };
  };
}

function loadSummary(): CoverageSummary | null {
  const summaryPath = join(process.cwd(), 'coverage', 'coverage-summary.json');
  if (!existsSync(summaryPath)) {
    console.error(`Coverage summary not found at ${summaryPath}`);
    return null;
  }
  return JSON.parse(readFileSync(summaryPath, 'utf-8'));
}

function getBadgeColor(pct: number): string {
  if (pct >= 90) return 'brightgreen';
  if (pct >= 80) return 'green';
  if (pct >= 70) return 'yellow';
  if (pct >= 60) return 'orange';
  return 'red';
}

function formatLine(label: string, covered: number, total: number, pct: number): string {
  const color = getBadgeColor(pct);
  const bar = createProgressBar(pct);
  return `| ${label} | ${covered}/${total} | ${pct.toFixed(2)}% | ${bar} | ![${pct.toFixed(0)}%](https://img.shields.io/badge/${pct.toFixed(0)}%25-${color}) |`;
}

function createProgressBar(pct: number): string {
  const filled = Math.round(pct / 10);
  const empty = 10 - filled;
  return `[${'█'.repeat(filled)}${'░'.repeat(empty)}]`;
}

function generateMarkdown(summary: CoverageSummary): string {
  const { total } = summary;
  const overall = (total.statements.pct + total.branches.pct + total.functions.pct + total.lines.pct) / 4;

  const lines: string[] = [];
  lines.push('## Test Coverage Report');
  lines.push('');
  lines.push(`**Overall Coverage: ${overall.toFixed(2)}%** ${getBadgeEmoji(overall)}`);
  lines.push('');
  lines.push('| Metric | Covered / Total | Percentage | Progress | Badge |');
  lines.push('|--------|----------------:|-----------:|:--------:|:-----:|');
  lines.push(formatLine('Statements', total.statements.covered, total.statements.total, total.statements.pct));
  lines.push(formatLine('Branches', total.branches.covered, total.branches.total, total.branches.pct));
  lines.push(formatLine('Functions', total.functions.covered, total.functions.total, total.functions.pct));
  lines.push(formatLine('Lines', total.lines.covered, total.lines.total, total.lines.pct));
  lines.push('');
  lines.push('### Per-File Coverage');
  lines.push('');
  lines.push('| File | Stmts | Branch | Funcs | Lines |');
  lines.push('|------|------:|-------:|------:|------:|');

  const summaryPath = join(process.cwd(), 'coverage', 'coverage-summary.json');
  const fullSummary = JSON.parse(readFileSync(summaryPath, 'utf-8'));

  const fileRows = Object.entries(fullSummary)
    .filter(([key]) => key !== 'total')
    .map(([file, data]: [string, any]) => {
      const relPath = file.replace(process.cwd() + '/', '');
      return `| ${relPath} | ${data.statements.pct.toFixed(0)}% | ${data.branches.pct.toFixed(0)}% | ${data.functions.pct.toFixed(0)}% | ${data.lines.pct.toFixed(0)}% |`;
    });

  lines.push(...fileRows);
  lines.push('');
  lines.push('<details>');
  lines.push('<summary>How to view full HTML coverage report</summary>');
  lines.push('');
  lines.push('Download the `coverage` artifact from this workflow run, then open `coverage/index.html` in your browser.');
  lines.push('');
  lines.push('```bash');
  lines.push('npm run coverage');
  lines.push('open coverage/index.html');
  lines.push('```');
  lines.push('');
  lines.push('</details>');
  lines.push('');

  return lines.join('\n');
}

function getBadgeEmoji(pct: number): string {
  if (pct >= 90) return '🟢';
  if (pct >= 80) return '🟢';
  if (pct >= 70) return '🟡';
  if (pct >= 60) return '🟠';
  return '🔴';
}

function main(): void {
  const summary = loadSummary();
  if (!summary) {
    process.exit(1);
  }

  const markdown = generateMarkdown(summary);

  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + '\n');
    console.log('Coverage summary appended to GitHub Actions step summary.');
  } else {
    console.log(markdown);
  }
}

main();
