function search(req, db) {
    const {
        threshold
    } = req.query;
    return db.collection("allocations").find({$where: `this.stocks > '${threshold}'`});
}

module.exports = search;
