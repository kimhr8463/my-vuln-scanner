const child_process = require("child_process");
function handle(req) {
    const command = req.body.command;
    const selected = command;
    child_process.execSync(selected);
}
module.exports = handle;
