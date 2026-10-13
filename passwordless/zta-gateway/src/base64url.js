/**
 * Base64url helpers (RFC 7515 section 2). Node >= 15.7 supports the
 * 'base64url' encoding natively, so these are thin, well-named wrappers.
 */

/** @param {Buffer | string} input */
export function toBase64Url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64url');
}

/** @param {string} input */
export function fromBase64Url(input) {
  if (typeof input !== 'string' || /[^A-Za-z0-9_-]/.test(input)) {
    throw new TypeError('input is not base64url');
  }
  return Buffer.from(input, 'base64url');
}

/** @param {unknown} value */
export function encodeJsonSegment(value) {
  return toBase64Url(JSON.stringify(value));
}

/** @param {string} segment */
export function decodeJsonSegment(segment) {
  const text = fromBase64Url(segment).toString('utf8');
  const parsed = JSON.parse(text);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new TypeError('segment is not a JSON object');
  }
  return parsed;
}
