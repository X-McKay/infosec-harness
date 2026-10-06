"use strict";

const crypto = require("crypto");

// Issue a session token.
// FIXED: the token comes from crypto.randomBytes, a CSPRNG. Its output does not
// depend on Math.random and cannot be reproduced from the Math.random state.
function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}

module.exports = { generateToken };
