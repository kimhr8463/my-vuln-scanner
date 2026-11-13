function findByThreshold(threshold, db) {
  return db.collection("allocations").find({ $where: `this.stocks > '${threshold}'` }); // vulnerable: two files
}

module.exports = { findByThreshold };
