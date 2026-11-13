const child_process = require("child_process");
function run(options) {
    const {body: {command}} = options;
    child_process.exec(command);
}
