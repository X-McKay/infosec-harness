// Merge user preferences (parsed request JSON) onto the stored defaults.
// VULNERABLE: every key is copied recursively, including "__proto__" and "constructor".
function mergePreferences(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      if (!target[key] || typeof target[key] !== "object") {
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
