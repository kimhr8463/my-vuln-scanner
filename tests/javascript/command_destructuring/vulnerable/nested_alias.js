function run(req) {
    const {body: {command: userCommand}} = req;
    require("child_process").execSync(userCommand);
}
