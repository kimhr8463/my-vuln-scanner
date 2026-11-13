// Static analysis fixture only; db is a MongoDB database handle.
const service = require("./nosql_service");

function direct(req, db) {
  return db.collection("allocations").find({ $where: `this.stocks > '${req.query.threshold}'` }); // vulnerable: direct
}

function intermediate(req, db) {
  const threshold = req.query.threshold;
  const condition = `this.stocks > '${threshold}'`;
  return db.collection("allocations").find({ $where: condition }); // vulnerable: intermediate
}

function throughArgument(req, db) {
  return helper(req.query.threshold, db);
}

function helper(threshold, db) {
  return db.collection("allocations").find({ $where: `this.stocks > '${threshold}'` }); // vulnerable: argument
}

function acrossFiles(req, db) {
  return service.findByThreshold(req.query.threshold, db);
}

module.exports = { direct, intermediate, throughArgument, acrossFiles };
