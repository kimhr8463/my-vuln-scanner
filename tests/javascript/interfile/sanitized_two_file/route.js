const dao = require("./dao");

function handle(req, db) {
    const threshold = Number.parseInt(req.query.threshold, 10);
    return dao.findByThreshold(db, threshold);
}

module.exports = handle;
