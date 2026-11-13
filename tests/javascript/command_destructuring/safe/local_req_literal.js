const child_process = require("child_process");
function run() {
    const req = {body: {command: "git status"}};
    const {body: {command: selectedCommand}} = req;
    child_process.exec(selectedCommand);
}
