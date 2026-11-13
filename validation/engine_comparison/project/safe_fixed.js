const child_process = require("child_process");
function handle(req) {
    const command = "git status";
    child_process.exec(command);
}
module.exports = handle;
