function search(req, db) {
    const threshold = req.query.threshold;
    return db.collection("allocations").find({$where: `this.stocks > '${threshold}'`});
}

module.exports = search;
