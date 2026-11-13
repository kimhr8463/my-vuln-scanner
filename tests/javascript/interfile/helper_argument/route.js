function buildWhere(threshold) {
    return {$where: `this.stocks > '${threshold}'`};
}

function handle(req, db) {
    const threshold = req.query.threshold;
    return db.collection("allocations").find(buildWhere(threshold));
}

module.exports = handle;
