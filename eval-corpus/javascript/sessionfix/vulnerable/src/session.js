"use strict";

const crypto = require("crypto");

// A minimal server-side session store keyed by a session id the client sends.
class SessionManager {
  constructor() {
    this.sessions = new Map(); // sid -> { user }
  }

  // Called when a request arrives carrying a session cookie.
  ensureSession(sid) {
    if (sid && this.sessions.has(sid)) {
      return sid;
    }
    const newSid = crypto.randomBytes(16).toString("hex");
    this.sessions.set(newSid, { user: null });
    return newSid;
  }

  // Authenticate the caller.
  // VULNERABLE: the session id presented before login is kept after login, so an id
  // an attacker planted in the victim's browser becomes an authenticated session.
  login(sid, user) {
    this.sessions.set(sid, { user });
    return sid;
  }

  userFor(sid) {
    const entry = this.sessions.get(sid);
    return entry ? entry.user : null;
  }
}

module.exports = { SessionManager };
