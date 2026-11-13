import assert from 'node:assert/strict';
import { retryProviderErrors } from './retry-errors.mjs';

const provider = { id: 'file://providers/agent-cli.mjs', label: 'fixture', config: { cli: 'codex', model: 'fixture' } };
const row = (error, gradingResult, prompt) => ({ error, gradingResult, prompt: { raw: prompt }, provider, testCase: { vars: {} } });
const report = { config: { providers: [provider] }, results: { results: [
  row(undefined, { pass: true }, 'passed'),
  row('Assertion failed', { pass: false }, 'grading failure'),
  row('CLI error', null, 'first provider error'),
  row('CLI error', null, 'second provider error'),
] } };
const calls = [];
const attempts = await retryProviderErrors(report, (options) => {
  assert.equal(options, provider);
  return { callApi: async (prompt) => { calls.push(prompt); return { error: 'still unavailable' }; } };
});
assert.deepEqual(calls, ['first provider error', 'second provider error']);
assert.deepEqual(attempts.map((attempt) => attempt.sourceIndex), [2, 3]);
assert.ok(attempts.every((attempt) => attempt.response.error && !attempt.gradingResult));
assert.equal(report.results.results.length, 4);
console.log('provider error replay: 4 passed');

// Successful provider-error replay must use the report's response contract.
const brief = "I'll review the instructions and begin.";
const preToolRow = row('CLI error', null, 'pre-tool sample');
preToolRow.testCase.metadata = { responseContract: 'pre-tool-v1' };
const replay = await retryProviderErrors({ ...report, results: { results: [preToolRow] } }, () => ({ callApi: async () => ({ output: brief }) }));
assert.equal(replay[0].gradingResult.pass, true);
const legacyReplay = await retryProviderErrors({ ...report, results: { results: [row('CLI error', null, 'legacy sample')] } }, () => ({ callApi: async () => ({ output: brief }) }));
assert.equal(legacyReplay[0].gradingResult.pass, false);
console.log('provider replay contract selection: 2 passed');
