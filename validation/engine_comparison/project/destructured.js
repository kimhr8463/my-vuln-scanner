const child_process = require("child_process");
function handle(req) {
    const {command} = req.body;
    child_process.exec(command);
}
module.exports = handle;
