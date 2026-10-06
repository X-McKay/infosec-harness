const zlib = require("zlib");

// Inflate an untrusted gzip buffer.
// FIXED: maxOutputLength caps the decompressed size, so an over-expanding input
// is rejected with a RangeError before it can exhaust memory.
const MAX_OUTPUT = 1 << 20; // 1 MiB

function inflate(buf) {
  return zlib.gunzipSync(buf, { maxOutputLength: MAX_OUTPUT });
}

module.exports = { inflate };
