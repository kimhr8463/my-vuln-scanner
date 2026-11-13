function directWhere(req) {
  return {$where: req.query.expression};
}

function intermediateWhere(req) {
  const threshold = req.query.threshold;
  const query = {$where: `this.stocks > '${threshold}'`};
  return query;
}

function rawMongoFilter(req, db) {
  return db.collection("allocations").find(req.body.filter);
}

function aliasMongoFilter(req, db) {
  const collection = db.collection("allocations");
  return collection.findOne(req.body.filter);
}

function dynamicWhereCandidate(threshold) {
  return {$where: `this.stocks > '${threshold}'`};
}
