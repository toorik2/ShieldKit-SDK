export class UnlockBuilderError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'UnlockBuilderError';
    this.code = code;
    Object.assign(this, extra);
  }
}
