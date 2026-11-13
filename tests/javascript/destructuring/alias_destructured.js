function search(req, db) {
    const {threshold: userThreshold} = req.query;
    return db.collection("allocations").find({$where: `this.stocks > '${userThreshold}'`});
}

module.exports = search;
