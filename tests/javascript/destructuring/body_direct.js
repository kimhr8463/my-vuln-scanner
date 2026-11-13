const child_process = require("child_process");

function run(req) {
    const command = req.body.command;
    child_process.exec(command);
}

module.exports = run;
