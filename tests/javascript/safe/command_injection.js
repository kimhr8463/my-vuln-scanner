const child_process = require("child_process");

function fixedCommand(req) {
  child_process.exec("git status");
  child_process.exec("git status", {shell: true});
}

function commandWithoutShell(req) {
  child_process.execFile("git", ["show", req.query.revision], {shell: false});
  child_process.spawn("git", [req.query.revision], {shell: false});
}
