const child_process = require("child_process");
function run() {
    child_process.exec("git status");
}
