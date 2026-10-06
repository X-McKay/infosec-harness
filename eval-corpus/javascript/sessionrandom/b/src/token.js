"use strict";

const crypto = require("crypto");

// Issue a session token.
function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}

module.exports = { generateToken };
