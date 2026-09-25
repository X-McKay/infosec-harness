const { exec } = require("child_process");

// Count lines in a file. VULNERABLE: untrusted path in a shell command.
function countLines(path, cb) {
  exec("wc -l " + path, (err, stdout) => cb(stdout));
}

module.exports = { countLines };
