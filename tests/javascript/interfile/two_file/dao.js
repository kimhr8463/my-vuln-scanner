function findByThreshold(db, threshold) {
    const query = {$where: `this.stocks > '${threshold}'`};
    return db.collection("allocations").find(query);
}

module.exports = {findByThreshold};
