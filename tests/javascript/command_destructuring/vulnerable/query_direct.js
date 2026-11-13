const child_process = require("child_process");
function run(req) {
    const command = req.query.command;
    child_process.execSync(command);
}
