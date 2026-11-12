import { access, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import AgentCliProvider from './agent-cli.mjs';
import grade from '../assertions/onboarding.cjs';

// Replay only provider errors, once per original sample. Assertion failures
// have a gradingResult and must never trigger more model calls here.
export async function retryProviderErrors(report, createProvider = (options) => new AgentCliProvider(options)) {
  const attempts = [];
  for (const [sourceIndex, row] of report.results.results.entries()) {
    if (!row.error || row.gradingResult) continue;
    const options = report.config.providers.find((provider) => provider.label === row.provider.label);
    if (!options?.config || options.id !== 'file://providers/agent-cli.mjs') {
      throw new Error(`Missing local CLI provider configuration for ${row.provider.label}`);
    }
    const response = await createProvider(options).callApi(row.prompt.raw, {}, {});
    const gradingResult = response.error ? null : grade(response.output, { vars: row.testCase.vars });
    attempts.push({ sourceIndex, provider: row.provider, testCase: row.testCase, response, gradingResult });
  }
  return attempts;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const input = process.argv[2];
  if (!input) throw new Error('Usage: npm run eval:retry-errors -- REPORT.json [OUTPUT.json]');
  const output = process.argv[3] ?? input.replace(/\.json$/, '') + '.retry-once.json';
  try {
    await access(output);
    throw new Error(`Retry report already exists: ${output}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const report = JSON.parse(await readFile(input, 'utf8'));
  const attempts = await retryProviderErrors(report);
  await writeFile(output, JSON.stringify({ source: input, attempts }, null, 2), { flag: 'wx' });
  const errors = attempts.filter((attempt) => attempt.response.error).length;
  const failed = attempts.filter((attempt) => attempt.gradingResult && !attempt.gradingResult.pass).length;
  console.log(JSON.stringify({ output, attempted: attempts.length, passed: attempts.length - errors - failed, failed, errors }));
  process.exitCode = errors || failed ? 100 : 0;
}
