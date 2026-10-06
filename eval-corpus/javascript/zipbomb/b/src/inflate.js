const zlib = require("zlib");

// Inflate an untrusted gzip buffer.
function inflate(buf) {
  return zlib.gunzipSync(buf);
}

module.exports = { inflate };
