const child_process = require("child_process");
function handle(req) {
    const count = Number.parseInt(req.query.count, 10);
    child_process.exec(`echo ${count}`);
}
module.exports = handle;
