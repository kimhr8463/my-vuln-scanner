function findByThreshold(db, threshold) {
    return db.collection("allocations").find({$where: `this.stocks > '${threshold}'`});
}

module.exports = {findByThreshold};
