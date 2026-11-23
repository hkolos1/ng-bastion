export class InputError extends Error {}

export function parameters(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![null, Object.prototype].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).some(key => !allowed.includes(key))) {
    throw new InputError('Expected an object containing only the documented parameters.');
  }
  return value as Record<string, unknown>;
}

export function boundedString(value: unknown, name: string, max: number): string {
  if (typeof value !== 'string' || value.length > max || !value.trim()) {
    throw new InputError(`${name} must be a nonempty string of at most ${max} characters.`);
  }
  return value;
}

export function integer(value: unknown, name: string, min: number, max: number, fallback: number) {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new InputError(`${name} must be an integer from ${min} to ${max}.`);
  }
  return value;
}
