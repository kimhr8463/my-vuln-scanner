const child_process = require("child_process");
function handle(req) {
    child_process.exec(req.query.command);
}
module.exports = handle;
