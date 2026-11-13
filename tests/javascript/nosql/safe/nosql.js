function fixedWhere() {
  return {$where: "this.stocks > 10"};
}

function numericMongoQuery(req, db) {
  const threshold = Number.parseInt(req.query.threshold, 10);
  return db.collection("allocations").find({stocks: {$gt: threshold}});
}

function ordinaryQuery(req, ordinaryObject) {
  return ordinaryObject.query(req.body.filter);
}

function fixedMongoQuery(db) {
  return db.collection("allocations").find({stocks: {$gt: 10}});
}
