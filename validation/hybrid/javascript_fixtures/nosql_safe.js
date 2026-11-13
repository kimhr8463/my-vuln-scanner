// Static analysis negative fixture only; do not execute.
function fixed(db) {
  return db.collection("allocations").find({ $where: "this.stocks > 100" }); // safe: fixed condition
}

function numeric(req, db) {
  const threshold = Number.parseInt(req.query.threshold, 10);
  return db.collection("allocations").find({ $where: `this.stocks > ${threshold}` }); // safe: numeric conversion
}

function noSink(req) {
  return req.query.threshold; // safe: input never reaches MongoDB query
}

function unrelatedQuery(req) {
  const localObject = { query: value => value };
  return localObject.query(req.query.threshold); // safe: no MongoDB find or $where
}

module.exports = { fixed, numeric, noSink, unrelatedQuery };
