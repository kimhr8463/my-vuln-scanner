function showGreeting() {
  const name = new URLSearchParams(window.location.search).get("name");
  document.querySelector("#greeting").innerHTML = name;
}

function showPrompt() {
  const name = prompt("Name?");
  document.write(name);
}

function showHash(element) {
  const fragment = location.hash;
  element.outerHTML = `<p>${fragment}</p>`;
}
