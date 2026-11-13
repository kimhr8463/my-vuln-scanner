const dao = require("./dao");

function search(req, db) {
    const {threshold} = req.query;
    return dao.findByThreshold(db, threshold);
}

module.exports = search;
