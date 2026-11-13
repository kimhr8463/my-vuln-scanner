const dao = require("./dao");
function dispatch(command) {
    const passed = command;
    return dao.run(passed);
}
module.exports = {dispatch};
