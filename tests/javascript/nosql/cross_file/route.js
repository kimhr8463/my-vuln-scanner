const dao = require("./dao");

function handler(req) {
  const {threshold} = req.query;
  return dao.search(threshold);
}

module.exports = handler;
