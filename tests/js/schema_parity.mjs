// Independent parity checker: it validates exported JSON Schema 2020-12 documents with Ajv and
// canonicalizes with an RFC 8785 library, using none of this repository's Python code.
//
//   node tests/js/schema_parity.mjs [--bundle DIR] [--fixtures FILE]
//
// Exit codes: 0 parity holds (a JSON report is printed), 1 a check failed, 2 blocked because a
// locked dependency is missing (run `npm ci` in tests/js). A missing dependency never skips.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

let Ajv2020;
let canonicalize;
try {
  const ajvModule = await import('ajv/dist/2020.js');
  Ajv2020 = ajvModule.default?.default ?? ajvModule.default ?? ajvModule;
  ({ default: canonicalize } = await import('canonicalize'));
} catch {
  process.stderr.write('BLOCKED: locked Node dependency missing (ajv, canonicalize); run npm ci in tests/js\n');
  process.exit(2);
}

const here = path.dirname(fileURLToPath(import.meta.url));
const options = { bundle: path.join(here, '..', '..', 'schemas'), fixtures: path.join(here, '..', 'fixtures', 'public', 'schema_parity.json') };
const args = process.argv.slice(2);
for (let index = 0; index < args.length; index += 2) {
  const flag = args[index];
  if ((flag !== '--bundle' && flag !== '--fixtures') || args[index + 1] === undefined) {
    process.stderr.write('usage: schema_parity.mjs [--bundle DIR] [--fixtures FILE]\n');
    process.exit(1);
  }
  options[flag.slice(2)] = path.resolve(args[index + 1]);
}

const failures = [];
const fail = (message) => failures.push(message);
const fixtures = JSON.parse(readFileSync(options.fixtures, 'utf8'));

// Every exported schema in the bundle must compile; the 2020-12 meta-schema is Ajv's own.
// Fully strict, strictTypes included: a bound keyword on the wrong type (for example minLength on
// an array) fails compilation instead of being ignored.
const ajv = new Ajv2020({ strict: true, strictTypes: true, allErrors: false });
const ids = [];
for (const file of readdirSync(options.bundle).filter((name) => name.endsWith('.schema.json')).sort()) {
  const schema = JSON.parse(readFileSync(path.join(options.bundle, file), 'utf8'));
  if (`${schema.$id}.schema.json` !== file) fail(`schema id does not match file name: ${file}`);
  ajv.addSchema(schema);
  ids.push(schema.$id);
}
ids.sort();
for (const id of ids) {
  try {
    ajv.getSchema(id);
  } catch (error) {
    fail(`schema does not compile: ${id}: ${error.message}`);
  }
}

const report = { compiledSchemas: ids, shape: {}, unicode: {}, jcs: {} };

for (const item of fixtures.shapeCases) {
  const validate = ajv.getSchema(item.schemaId);
  if (validate === undefined) {
    fail(`unknown schema for case ${item.caseId}`);
    continue;
  }
  const accepted = validate(item.instance) === true;
  report.shape[item.caseId] = accepted;
  // JSON Schema expresses shape only; semantic_invalid cases are shape-valid by construction.
  const expected = item.kind !== 'shape_invalid';
  if (accepted !== expected) fail(`shape verdict differs from fixture kind ${item.kind}: ${item.caseId}`);
}

for (const item of fixtures.unicodeCases) {
  const text = item.text;
  const wellFormed = text.isWellFormed();
  const result = {
    wellFormed,
    scalarLength: wellFormed ? [...text].length : null,
    utf16Length: text.length,
    utf8Hex: wellFormed ? Buffer.from(text, 'utf8').toString('hex') : null,
  };
  report.unicode[item.caseId] = result;
  for (const key of Object.keys(result)) {
    if (result[key] !== item[key]) fail(`unicode ${key} differs from fixture: ${item.caseId}`);
  }
}

for (const item of fixtures.jcsVectors) {
  const bytes = Buffer.from(canonicalize(item.value), 'utf8');
  const result = { canonicalHex: bytes.toString('hex') };
  if (item.domain !== undefined) {
    result.digest = createHash('sha256')
      .update(Buffer.concat([Buffer.from(`${item.domain}\n`, 'utf8'), bytes]))
      .digest('hex');
    if (result.digest !== item.digest) fail(`digest differs from fixture: ${item.caseId}`);
  }
  report.jcs[item.caseId] = result;
  if (result.canonicalHex !== item.canonicalUtf8Hex) fail(`canonical bytes differ from fixture: ${item.caseId}`);
}

if (failures.length > 0) {
  for (const message of failures) process.stderr.write(`FAIL: ${message}\n`);
  process.exit(1);
}
process.stdout.write(`${JSON.stringify(report)}\n`);
