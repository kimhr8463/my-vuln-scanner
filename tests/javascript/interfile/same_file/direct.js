function direct(req, db) {
    const threshold = req.query.threshold;
    const query = {$where: `this.stocks > '${threshold}'`};
    return db.collection("allocations").find(query);
}

module.exports = direct;
