const service = require("./service");

function handle(req, db) {
    const threshold = req.query.threshold;
    return service.lookup(db, threshold);
}

module.exports = handle;
