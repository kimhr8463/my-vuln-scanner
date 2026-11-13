const child_process = require("child_process");
function run(req) {
    const {command} = req.body;
    if (command === "git status") {
        child_process.exec("git status");
    } else {
        child_process.exec("git log -1");
    }
}
