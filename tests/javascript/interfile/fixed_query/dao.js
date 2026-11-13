function findFixed(db) {
    const query = {$where: "this.stocks > 10"};
    return db.collection("allocations").find(query);
}

module.exports = {findFixed};
