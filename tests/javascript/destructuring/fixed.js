function search(db) {
    const threshold = 100;
    return db.collection("allocations").find({$where: `this.stocks > ${threshold}`});
}

module.exports = search;
