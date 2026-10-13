#!/usr/bin/env node
/**
 * CI guardrails for the policy-as-code tree:
 *  - every .json parses
 *  - Conditional Access policies are committed report-only, exclude the break-glass group,
 *    and use only known placeholders
 *  - authentication strengths reference built-in ids
 *  - compliance policies block with zero grace
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const KNOWN_PLACEHOLDERS = new Set(['BREAK_GLASS_GROUP_ID', 'PILOT_GROUP_ID', 'TRUSTED_NAMED_LOCATION_ID', 'CUTOVER_DATETIME']);
const BUILTIN_STRENGTHS = new Set(['00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000004']);
const errors = [];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git') continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (name.endsWith('.json')) out.push(p);
  }
  return out;
}

for (const file of walk(root)) {
  const rel = relative(root, file);
  const text = readFileSync(file, 'utf8');
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    errors.push(`${rel}: invalid JSON (${err.message})`);
    continue;
  }
  for (const m of text.matchAll(/\{\{([A-Z0-9_]+)\}\}/g)) {
    if (!KNOWN_PLACEHOLDERS.has(m[1])) errors.push(`${rel}: unknown placeholder {{${m[1]}}}`);
  }
  if (rel.startsWith('entra/conditional-access/')) {
    if (!/^CA\d{3}-/.test(rel.split('/').pop())) errors.push(`${rel}: file name must start with CAnnn-`);
    if (doc.state !== 'enabledForReportingButNotEnforced') errors.push(`${rel}: must be committed report-only, got ${doc.state}`);
    if (!doc.displayName?.startsWith(rel.split('/').pop().slice(0, 5))) errors.push(`${rel}: displayName must start with the policy code`);
    const isWorkload = Boolean(doc.conditions?.clientApplications);
    if (!isWorkload && !doc.conditions?.users?.excludeGroups?.includes('{{BREAK_GLASS_GROUP_ID}}')) errors.push(`${rel}: must exclude {{BREAK_GLASS_GROUP_ID}}`);
    const strength = doc.grantControls?.authenticationStrength?.id;
    if (strength && !BUILTIN_STRENGTHS.has(strength)) errors.push(`${rel}: unknown authentication strength ${strength}`);
    if (strength && doc.grantControls?.builtInControls?.includes('mfa')) errors.push(`${rel}: authenticationStrength cannot be combined with the mfa built-in control`);
    if (!doc.grantControls) errors.push(`${rel}: grantControls missing`);
  }
  if (rel.startsWith('intune/compliance/')) {
    const rule = doc.scheduledActionsForRule?.[0]?.scheduledActionConfigurations?.[0];
    if (!rule || rule.actionType !== 'block' || rule.gracePeriodHours !== 0) errors.push(`${rel}: compliance policies must block with gracePeriodHours 0`);
  }
}

if (errors.length) {
  console.error(errors.map((e) => ` - ${e}`).join('\n'));
  process.exit(1);
}
console.log('passwordless: all JSON policies valid');
