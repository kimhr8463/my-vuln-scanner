const childProcess = require("child_process");

function run(command) {
  childProcess.exec(command); // vulnerable: two files
}

module.exports = { run };
