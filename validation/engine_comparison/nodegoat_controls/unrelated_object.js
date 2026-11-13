function handle(req) {
    const threshold = req.query.threshold;
    return {$where: `display threshold ${threshold}`};
}
module.exports = handle;
