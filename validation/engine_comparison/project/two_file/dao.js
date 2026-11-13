const child_process = require("child_process");
function run(command) {
    child_process.exec(command);
}
module.exports = {run};
