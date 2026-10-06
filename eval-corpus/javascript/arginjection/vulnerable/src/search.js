const { execFile } = require("child_process");

// Search the notes file for a user-supplied term and return the matching lines.
// VULNERABLE: `term` occupies an option position, so a value beginning with "-" is
// parsed by grep as an option (e.g. --version) rather than a search pattern.
function search(term, file, cb) {
  execFile("grep", [term, file], (err, stdout) => cb(stdout));
}

module.exports = { search };
