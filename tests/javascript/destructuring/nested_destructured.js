const child_process = require("child_process");

function run(req) {
    const {body: {command}} = req;
    child_process.exec(command);
}

module.exports = run;
