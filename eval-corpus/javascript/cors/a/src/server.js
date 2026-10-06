const http = require("http");

// Only the first-party app origins may read profile responses with credentials.
const ALLOWED_ORIGINS = new Set(["https://app.example.com", "https://admin.example.com"]);

// Return the signed-in user's profile to the single-page app.
function handleProfile(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Vary", "Origin");
  const session = req.headers.cookie || "";
  const user = session.includes("session=") ? "alice" : null;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(user ? { user, email: "alice@example.invalid" } : { user: null }));
}

function createServer() {
  return http.createServer(handleProfile);
}

module.exports = { handleProfile, createServer };
