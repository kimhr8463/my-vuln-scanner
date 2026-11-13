// Static analysis fixture only; do not execute.
const childProcess = require("child_process");
const service = require("./command_service");

function direct(req) {
  childProcess.exec(req.body.command); // vulnerable: direct
}

function intermediate(req) {
  const command = req.query.command;
  childProcess.execSync(command); // vulnerable: intermediate
}

function throughArgument(req) {
  helper(req.body.command);
}

function helper(command) {
  childProcess.exec(command); // vulnerable: argument
}

function acrossFiles(req) {
  service.run(req.query.command);
}

module.exports = { direct, intermediate, throughArgument, acrossFiles };
