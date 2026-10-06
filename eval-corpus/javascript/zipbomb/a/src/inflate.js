const zlib = require("zlib");

// Inflate an untrusted gzip buffer.
const MAX_OUTPUT = 1 << 20; // 1 MiB

function inflate(buf) {
  return zlib.gunzipSync(buf, { maxOutputLength: MAX_OUTPUT });
}

module.exports = { inflate };
