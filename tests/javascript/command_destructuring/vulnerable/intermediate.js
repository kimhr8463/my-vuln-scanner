const child_process = require("child_process");
function run(req) {
    const {command} = req.body;
    const selectedCommand = command;
    child_process.exec(selectedCommand);
}
