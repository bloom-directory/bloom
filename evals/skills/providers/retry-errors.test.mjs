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
