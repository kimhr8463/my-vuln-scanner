const child_process = require("child_process");
function run(req) {
    const {command} = req.body;
    const selectedCommand = "git log -1";
    child_process.exec(selectedCommand);
    return command;
}
