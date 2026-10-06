// Merge user preferences (parsed request JSON) onto the stored defaults.
// FIXED: keys that can reach a shared prototype are skipped, and only own keys descend.
const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function mergePreferences(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.has(key)) continue;
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      if (!Object.prototype.hasOwnProperty.call(target, key) || typeof target[key] !== "object") {
        target[key] = {};
      }
      mergePreferences(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

module.exports = { mergePreferences };
