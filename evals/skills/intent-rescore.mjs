#!/usr/bin/env node
// Judge saved responses or the calibration cases, without regenerating answers.
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { judgeIntent } from './assertions/onboarding.cjs';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('Usage: node intent-rescore.mjs INPUT.json OUTPUT.json');
const source = JSON.parse(await readFile(input, 'utf8'));
const cases = Array.isArray(source) ? source : source.results?.results.map((row, index) => ({
  id: `${row.provider?.label ?? 'model'}:${row.vars?.platform ?? index}:${index}`,
  platformContext: row.vars?.platformContext,
  expected: row.vars?.expected,
  response: row.response?.output,
  provider_error: row.response?.error ?? (typeof row.response?.output === 'string' ? undefined : row.error),
}));
if (!cases?.length || !cases.some((item) => !item.provider_error && typeof item.response === 'string')) throw new Error('No judgeable saved responses');
const results = [];
for (const item of cases) {
  if (item.provider_error || typeof item.response !== 'string') {
    results.push({ id: item.id, provider_error: item.provider_error ?? 'No model response' });
    continue;
  }
  try {
    const judgment = await judgeIntent(item.response, { vars: { platformContext: item.platformContext } });
    results.push({ id: item.id, expected: item.expected, ...judgment, ...(item.expected ? { matches_expected: judgment.decision === item.expected } : {}) });
  } catch (error) {
    results.push({ id: item.id, judge_error: error.message });
  }
}
const counts = Object.fromEntries(['proceed', 'refuse', 'blocked'].map((decision) => [decision, results.filter((row) => row.decision === decision).length]));
const summary = { ...counts, provider_errors: results.filter((row) => row.provider_error).length, judge_errors: results.filter((row) => row.judge_error).length, ...(cases.some((item) => item.expected) ? { calibration_mismatches: results.filter((row) => row.matches_expected === false).length } : {}), correctness: 'not measured by this intent eval' };
await mkdir(dirname(resolve(output)), { recursive: true });
await writeFile(output, `${JSON.stringify({ input: resolve(input), summary, results }, null, 2)}\n`, { mode: 0o600 });
await chmod(output, 0o600);
console.log(JSON.stringify(summary));
process.exitCode = summary.provider_errors || summary.judge_errors ? 2 : summary.calibration_mismatches ? 1 : 0;
