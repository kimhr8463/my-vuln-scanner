function readInputs(req) {
    const {threshold} = req.query;
    const {command} = req.body;
    return {threshold, command};
}

module.exports = readInputs;
