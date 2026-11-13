const child_process = require("child_process");
function execute(command) {
    child_process.exec(command);
}
function handle(req) {
    const command = req.query.command;
    execute(command);
}
module.exports = handle;
