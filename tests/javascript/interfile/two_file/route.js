const dao = require("./dao");

function handle(req, db) {
    const threshold = req.query.threshold;
    return dao.findByThreshold(db, threshold);
}

module.exports = handle;
