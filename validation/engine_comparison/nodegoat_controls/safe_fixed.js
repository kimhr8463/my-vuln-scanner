function handle(req, collection) {
    const threshold = 100;
    return collection.find({$where: `this.stocks > ${threshold}`});
}
module.exports = handle;
