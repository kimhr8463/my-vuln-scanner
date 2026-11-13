const collection = {find: query => query};
function query(threshold) {
    return collection.find({$where: `this.stocks > '${threshold}'`});
}
module.exports = {query};
