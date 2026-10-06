const http = require("http");

// Return the signed-in user's profile to the single-page app.
// VULNERABLE: any Origin is echoed back together with Allow-Credentials, so a page on any
// site can read the profile with the visitor's session cookie.
function handleProfile(req, res) {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
  const session = req.headers.cookie || "";
  const user = session.includes("session=") ? "alice" : null;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(user ? { user, email: "alice@example.invalid" } : { user: null }));
}

function createServer() {
  return http.createServer(handleProfile);
}

module.exports = { handleProfile, createServer };
