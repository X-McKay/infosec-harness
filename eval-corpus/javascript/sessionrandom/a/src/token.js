"use strict";

// Issue a session token.
function generateToken() {
  let token = "";
  for (let i = 0; i < 16; i++) {
    // 0..15 -> one hex digit, 16 digits total.
    token += Math.floor(Math.random() * 16).toString(16);
  }
  return token;
}

module.exports = { generateToken };
