// ===== Vulnerable: DOM XSS =====

function vulnerableSearch() {
    const name = new URLSearchParams(window.location.search).get("name");

    // ruleid: javascript-dom-xss-taint
    document.querySelector("#greeting").innerHTML = name;
}

function vulnerablePrompt() {
    const name = prompt("Name?");

    // ruleid: javascript-dom-xss-taint
    document.write(name);
}

function vulnerableHash(element) {
    const fragment = location.hash;

    // ruleid: javascript-dom-xss-taint
    element.outerHTML = `<p>${fragment}</p>`;
}

// ===== Safe: No DOM XSS =====

function safeTextContent() {
    const name = new URLSearchParams(window.location.search).get("name");

    // ok: javascript-dom-xss-taint
    document.querySelector("#greeting").textContent = name;
}

function safeFixedHtml() {
    // ok: javascript-dom-xss-taint
    document.querySelector("#greeting").innerHTML = "<strong>Hello</strong>";
}

function safeFixedParameter() {
    const fixed = new URLSearchParams("?name=trusted").get("name");

    // ok: javascript-dom-xss-taint
    document.querySelector("#greeting").innerHTML = fixed;
}
