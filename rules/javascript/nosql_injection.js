// ruleid: javascript-mongodb-nosql-injection-taint
const direct = {$where: req.query.filter};

function intermediate(req) {
  const userClause = req.body.condition;
  const expression = `this.stocks > '${userClause}'`;
  // ruleid: javascript-mongodb-nosql-injection-taint
  return {$where: expression};
}

function directMongoQuery(req, db) {
  // ruleid: javascript-mongodb-nosql-injection-taint
  return db.collection("allocations").find(req.body.filter);
}

function aliasMongoQuery(req, db) {
  const collection = db.collection("allocations");
  // ruleid: javascript-mongodb-nosql-injection-taint
  return collection.findOne(req.body.filter);
}

function objectInjection(req) {
  // ruleid: javascript-mongodb-nosql-injection-taint
  return {$where: req.body.condition};
}

function dynamicWhere(threshold) {
  // ruleid: javascript-mongodb-dynamic-where-candidate
  return {$where: `this.stocks > '${threshold}'`};
}

function fixedWhere() {
  // ok: javascript-mongodb-dynamic-where-candidate
  return {$where: "this.stocks > 10"};
}

function safeMongoQuery(req, db) {
  const threshold = Number.parseInt(req.query.threshold, 10);
  // ok: javascript-mongodb-nosql-injection-taint
  return db.collection("allocations").find({stocks: {$gt: threshold}});
}

function unrelatedQuery(req, ordinaryObject) {
  // ok: javascript-mongodb-nosql-injection-taint
  return ordinaryObject.query(req.body.filter);
}
