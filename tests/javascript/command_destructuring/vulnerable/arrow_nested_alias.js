const child_process = require("child_process");
const handler = {};
handler.run = (req) => {
    const {body: {command: selectedCommand}} = req;
    child_process.execSync(selectedCommand);
};
