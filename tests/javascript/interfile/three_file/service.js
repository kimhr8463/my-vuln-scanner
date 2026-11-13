const dao = require("./dao");

function lookup(db, threshold) {
    const passedThreshold = threshold;
    return dao.findByThreshold(db, passedThreshold);
}

module.exports = {lookup};
