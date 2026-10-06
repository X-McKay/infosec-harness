const { execFile } = require("child_process");

// Search the notes file for a user-supplied term and return the matching lines.
function search(term, file, cb) {
  execFile("grep", ["--", term, file], (err, stdout) => cb(stdout));
}

module.exports = { search };
