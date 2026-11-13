const child_process = require("child_process");

function runFromHttp(req) {
  const command = "git show " + req.query.revision;
  child_process.exec(command);
}

function runFromCli() {
  const command = `ls ${process.argv[2]}`;
  child_process.execSync(command);
}

function runDirect(req) {
  require("child_process").exec(req.body.command);
}
