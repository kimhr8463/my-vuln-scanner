const child_process = require("child_process");
function run(options) {
    const {command} = options;
    child_process.exec(command);
}
