const zlib = require("zlib");

// Inflate an untrusted gzip buffer.
// VULNERABLE: no limit on the decompressed output size (CWE-409 / CWE-400). A
// small compressed input can expand to an arbitrarily large buffer in memory.
function inflate(buf) {
  return zlib.gunzipSync(buf);
}

module.exports = { inflate };
