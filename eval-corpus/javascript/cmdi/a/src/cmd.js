const { execFile } = require("child_process");

// Count lines in a file. FIXED: argument vector, no shell.
function countLines(path, cb) {
  execFile("wc", ["-l", path], (err, stdout) => cb(stdout));
}

module.exports = { countLines };
