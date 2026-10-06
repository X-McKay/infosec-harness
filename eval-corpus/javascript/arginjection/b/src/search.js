const { execFile } = require("child_process");

// Search the notes file for a user-supplied term and return the matching lines.
// FIXED: "--" ends grep's option parsing, so `term` is always treated as a search
// pattern and can never be interpreted as an option.
function search(term, file, cb) {
  execFile("grep", ["--", term, file], (err, stdout) => cb(stdout));
}

module.exports = { search };
