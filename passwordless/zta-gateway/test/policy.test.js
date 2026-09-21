import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyAmr, evaluateAccess, isAppOnlyToken, STRENGTH } from '../src/policy.js';
import { userClaims, appClaims } from './helpers.js';

test('classifyAmr maps Entra amr values to strengths', () => {
  assert.equal(classifyAmr(['fido', 'mfa']), STRENGTH.PHISHING_RESISTANT);
  assert.equal(classifyAmr(['hwk', 'mfa', 'ngcmfa']), STRENGTH.PHISHING_RESISTANT);
  assert.equal(classifyAmr(['swk', 'rsa', 'mfa']), STRENGTH.PASSWORDLESS);
  assert.equal(classifyAmr(['pwd', 'rsa', 'ngcmfa', 'mfa']), STRENGTH.MFA, 'Authenticator push is MFA, not phishing-resistant');
  assert.equal(classifyAmr(['pwd', 'totp', 'mfa']), STRENGTH.MFA);
  assert.equal(classifyAmr(['pwd']), 'singleFactor');
  assert.equal(classifyAmr(['x509']), 'singleFactor', 'single-factor CBA is not MFA');
  assert.equal(classifyAmr(['x509', 'hwk', 'mfa']), STRENGTH.PHISHING_RESISTANT, 'multi-factor CBA emits hwk');
  assert.equal(classifyAmr(undefined), 'unknown');
  assert.equal(classifyAmr('fido'), 'unknown');
});

test('default requirement demands phishing-resistant sign-in for users', () => {
  assert.equal(evaluateAccess(userClaims()).allowed, true);
  const push = evaluateAccess(userClaims({ amr: ['pwd', 'rsa', 'mfa'] }));
  assert.equal(push.allowed, false);
  assert.deepEqual(push.reasons, ['strength_insufficient:mfa']);
  const missing = evaluateAccess(userClaims({ amr: undefined }));
  assert.equal(missing.allowed, false, 'missing amr fails closed');
  assert.deepEqual(missing.reasons, ['strength_insufficient:unknown']);
});

test('minimumStrength can be relaxed', () => {
  const phone = userClaims({ amr: ['swk', 'rsa', 'mfa'] });
  assert.equal(evaluateAccess(phone, { minimumStrength: STRENGTH.PASSWORDLESS }).allowed, true);
  assert.equal(evaluateAccess(phone, { minimumStrength: STRENGTH.PHISHING_RESISTANT }).allowed, false);
  assert.equal(evaluateAccess(userClaims({ amr: ['pwd'] }), { minimumStrength: STRENGTH.NONE }).allowed, true);
  assert.throws(() => evaluateAccess(userClaims(), { minimumStrength: 'strong' }), TypeError);
});

test('app-only tokens must come from certificate client authentication', () => {
  assert.equal(isAppOnlyToken(appClaims()), true);
  assert.equal(isAppOnlyToken(appClaims({ idtyp: undefined })), true, 'roles without scp implies app');
  assert.equal(isAppOnlyToken(userClaims()), false);
  assert.equal(evaluateAccess(appClaims()).allowed, true);
  const secret = evaluateAccess(appClaims({ azpacr: '1' }));
  assert.deepEqual(secret.reasons, ['app_client_auth_not_certificate']);
  assert.equal(evaluateAccess(appClaims({ azpacr: '1' }), { requireCertificateForApps: false }).allowed, true);
  assert.deepEqual(evaluateAccess(appClaims(), { allowAppOnly: false }).reasons, ['app_only_not_allowed']);
  assert.deepEqual(evaluateAccess(userClaims(), { allowUsers: false }).reasons, ['user_tokens_not_allowed']);
});

test('authentication context drives a step-up challenge', () => {
  const noCtx = evaluateAccess(userClaims(), { authContext: 'c1' });
  assert.equal(noCtx.allowed, false);
  assert.equal(noCtx.stepUpAuthContext, 'c1');
  assert.deepEqual(noCtx.reasons, ['auth_context_missing']);
  const withCtx = evaluateAccess(userClaims({ acrs: ['c1', 'c2'] }), { authContext: 'c1' });
  assert.equal(withCtx.allowed, true);
  assert.equal(withCtx.stepUpAuthContext, undefined);
});

test('CAE capability and client allow-list', () => {
  assert.deepEqual(evaluateAccess(userClaims(), { requireCaeCapable: true }).reasons, ['client_not_cae_capable']);
  assert.equal(evaluateAccess(userClaims({ xms_cc: ['cp1'] }), { requireCaeCapable: true }).allowed, true);
  assert.deepEqual(evaluateAccess(userClaims(), { allowedClientIds: ['other'] }).reasons, ['client_not_allowed']);
  assert.equal(evaluateAccess(userClaims(), { allowedClientIds: ['client-app-1'] }).allowed, true);
});
