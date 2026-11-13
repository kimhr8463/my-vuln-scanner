// Static analysis negative fixture only; do not execute.
const childProcess = require("child_process");

function fixed() {
  childProcess.exec("echo fixed"); // safe: fixed command
}

function allowlisted(req) {
  const choice = req.body.command;
  if (choice !== "status" && choice !== "version") return;
  const command = choice === "status" ? "echo status" : "echo version";
  childProcess.exec(command); // safe: fixed allowlist mapping
}

function numeric(req) {
  const count = Number.parseInt(req.query.command, 10);
  childProcess.exec(`echo ${count}`); // safe: numeric conversion
}

function noSink(req) {
  return req.query.command; // safe: input never reaches command execution
}

module.exports = { fixed, allowlisted, numeric, noSink };
