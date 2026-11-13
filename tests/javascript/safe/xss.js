function showGreeting() {
  const name = new URLSearchParams(window.location.search).get("name");
  document.querySelector("#greeting").textContent = name;
}

function showFixedHtml() {
  document.querySelector("#greeting").innerHTML = "<strong>Hello</strong>";
}

function showFixedUrlParameter() {
  const fixed = new URLSearchParams("?name=trusted").get("name");
  document.querySelector("#greeting").innerHTML = fixed;
}
