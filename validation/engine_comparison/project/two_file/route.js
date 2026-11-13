const dao = require("./dao");
function handle(req) {
    const command = req.query.command;
    return dao.run(command);
}
module.exports = handle;
