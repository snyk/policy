/**
 * Strips functions from an object
 * @param obj (*mutates!*) the object from which to strip functions
 */
export function stripFunctions<T>(obj: T) {
  // strip functions (as they don't land in the final config)
  for (const key in obj) {
    if (typeof obj[key] === 'function') {
      delete obj[key];
    }
  }

  return obj;
}
