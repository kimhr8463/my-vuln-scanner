function search(req, db) {
    const {command} = req.body;
    return db.collection("allocations").find({$where: `this.name == '${command}'`});
}

module.exports = search;
