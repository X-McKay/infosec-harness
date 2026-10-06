const { execFile } = require("child_process");

// Count lines in a file.
function countLines(path, cb) {
  execFile("wc", ["-l", path], (err, stdout) => cb(stdout));
}

module.exports = { countLines };
