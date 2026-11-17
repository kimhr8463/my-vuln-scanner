const child_process = require("child_process");

// ===== Vulnerable: Command Injection =====

function vulnerableQuery(req) {
    const command = "git show " + req.query.revision;

    // ruleid: javascript-command-injection-taint
    child_process.exec(command);
}

function vulnerableCli() {
    const command = `ls ${process.argv[2]}`;

    // ruleid: javascript-command-injection-taint
    child_process.execSync(command);
}

function vulnerableBody(req) {
    // ruleid: javascript-command-injection-taint
    child_process.exec(req.body.command);
}

// ===== Safe: No Command Injection =====

function safeFixedCommand(req) {
    // ok: javascript-command-injection-taint
    child_process.exec("git status");
}

function safeExecFile(req) {
    // ok: javascript-command-injection-taint
    child_process.execFile("git", ["show", req.query.revision]);
}

function safeSpawn(req) {
    // ok: javascript-command-injection-taint
    child_process.spawn("git", [req.query.revision], {
        shell: false
    });
}
