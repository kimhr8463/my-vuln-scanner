const dao = require("./dao");
function handle(req) {
    const {threshold} = req.query;
    return dao.query(threshold);
}
module.exports = handle;
