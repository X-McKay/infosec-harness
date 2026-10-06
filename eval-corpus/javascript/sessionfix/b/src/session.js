"use strict";

const crypto = require("crypto");

// A minimal server-side session store keyed by a session id the client sends.
class SessionManager {
  constructor() {
    this.sessions = new Map(); // sid -> { user }
  }

  ensureSession(sid) {
    if (sid && this.sessions.has(sid)) {
      return sid;
    }
    const newSid = crypto.randomBytes(16).toString("hex");
    this.sessions.set(newSid, { user: null });
    return newSid;
  }

  // Authenticate the caller.
  login(sid, user) {
    this.sessions.delete(sid);
    const newSid = crypto.randomBytes(16).toString("hex");
    this.sessions.set(newSid, { user });
    return newSid;
  }

  userFor(sid) {
    const entry = this.sessions.get(sid);
    return entry ? entry.user : null;
  }
}

module.exports = { SessionManager };
