const child_process = require("child_process");
const run = (req) => {
    const {command} = req.body;
    child_process.exec(command);
};
