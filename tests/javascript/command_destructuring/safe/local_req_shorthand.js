const child_process = require("child_process");
function run() {
    const req = {body: {command: "git status"}};
    const {command} = req.body;
    child_process.exec(command);
}
