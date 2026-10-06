import assert from "node:assert/strict";
import test from "node:test";
import { isDark, parseTheme } from "./theme.ts";

test("stored theme preferences fall back to the system setting", () => {
  assert.equal(parseTheme("dark"), "dark");
  assert.equal(parseTheme("light"), "light");
  for (const value of [null, undefined, "", "Dark", "solarized", 1])
    assert.equal(parseTheme(value), "system");
});

test("explicit choices override the system preference", () => {
  assert.equal(isDark("dark", false), true);
  assert.equal(isDark("light", true), false);
  assert.equal(isDark("system", true), true);
  assert.equal(isDark("system", false), false);
});
