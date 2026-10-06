"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { SessionManager } = require("../src/session");

test("the session id is regenerated on login (no fixation)", () => {
  const mgr = new SessionManager();

  // Attacker plants a session id in the victim's browser.
  const planted = mgr.ensureSession(null);

  // Victim logs in while carrying the planted id.
  const afterLogin = mgr.login(planted, "victim");

  // positive control: the id the victim ends up with is authenticated.
  assert.strictEqual(mgr.userFor(afterLogin), "victim");

  // FIXED: the planted id is destroyed and no longer authenticates.
  assert.notStrictEqual(afterLogin, planted);
  assert.strictEqual(mgr.userFor(planted), null);
});
