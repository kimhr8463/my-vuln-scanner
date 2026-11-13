const child_process = require("child_process");
function run(req) {
    const {command: userCommand} = req.body;
    child_process.execSync(userCommand);
}
