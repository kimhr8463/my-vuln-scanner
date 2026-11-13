const service = require("./service");
function handle(req) {
    const command = req.query.command;
    return service.dispatch(command);
}
module.exports = handle;
