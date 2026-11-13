function handle(req, db) {
    const threshold = Number.parseInt(req.query.threshold, 10);
    const query = {$where: `this.stocks > ${threshold}`};
    return db.collection("allocations").find(query);
}

module.exports = handle;
