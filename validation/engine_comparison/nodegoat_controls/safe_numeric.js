function handle(req, collection) {
    const threshold = Number.parseInt(req.query.threshold, 10);
    if (!Number.isInteger(threshold)) return null;
    return collection.find({$where: `this.stocks > ${threshold}`});
}
module.exports = handle;
