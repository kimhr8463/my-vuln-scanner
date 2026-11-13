function search(req, db) {
    const {body: {command}} = req;
    return db.collection("allocations").find({$where: `this.name == '${command}'`});
}

module.exports = search;
