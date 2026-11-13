const child_process = require("child_process");
function handle(req) {
    const {command: userCommand} = req.body;
    child_process.exec(userCommand);
}
module.exports = handle;
