/**
 * Error raised for any token that must be rejected. `code` is stable and
 * safe to surface to clients; `message` is for logs.
 */
export class TokenError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = 'TokenError';
    this.code = code;
  }
}
