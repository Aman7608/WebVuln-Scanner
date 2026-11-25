// Small helpers used on every page.

// The CSRF token from <meta name="csrf-token">. Every POST from JavaScript must
// send it in the X-CSRF-Token header, or the server refuses the request.
function csrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : "";
}

// POST JSON to our own API with the CSRF token added.
function postJson(url, body) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: JSON.stringify(body || {}),
  });
}

// Forms with data-confirm="..." ask before they are sent (e.g. "Delete this scan?").
// Inline onclick="" is not allowed by our Content-Security-Policy, so it is done here.
document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

// Copy buttons: <button data-copy="text to copy">
document.querySelectorAll("button[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      const old = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = old), 1200);
    } catch (error) {
      // Clipboard not available: the user can still select the text by hand
    }
  });
});
