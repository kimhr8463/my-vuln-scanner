const child_process = require("child_process");
function handle(req) {
    const {body: {command}} = req;
    child_process.exec(command);
}
module.exports = handle;
