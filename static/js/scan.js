// New Scan page: sends the form to the API and shows live progress.

const form = document.getElementById("scan-form");
const errorBox = document.getElementById("form-error");
const startButton = document.getElementById("start-button");
const progressCard = document.getElementById("progress-card");

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function readForm() {
  const data = new FormData(form);
  return {
    target_url: data.get("target_url").trim(),
    modules: data.getAll("modules"),
    max_depth: Number(data.get("max_depth")),
    max_pages: Number(data.get("max_pages")),
    timeout: Number(data.get("timeout")),
    max_requests: Number(data.get("max_requests")),
    delay: Number(data.get("delay")),
    authorized: document.getElementById("authorized").checked,
  };
}

// Quick checks in the browser. The server checks everything again.
function validate(values) {
  if (!values.target_url) return "Please enter a target URL.";
  if (!/^https?:\/\//i.test(values.target_url)) return "The URL must start with http:// or https://";
  if (values.modules.length === 0) return "Select at least one scan module.";
  if (!values.authorized) return "Please confirm that you are authorized to scan this target.";
  return null;
}

function updateProgress(scan) {
  document.getElementById("progress-fill").style.width = scan.progress + "%";
  document.getElementById("progress-percent").textContent = scan.progress + "%";
  document.getElementById("progress-step").textContent = scan.current_step || "Starting…";
  document.getElementById("progress-counts").textContent =
    `${scan.requests_sent || 0} requests sent so far`;
}

async function pollScan(scanId) {
  try {
    const response = await fetch(`/api/scans/${scanId}`);
    const scan = await response.json();
    updateProgress(scan);
    if (scan.status === "completed" || scan.status === "failed") {
      window.location.href = `/scans/${scanId}`;
      return;
    }
  } catch (error) {
    // Network hiccup: just try again on the next tick
  }
  setTimeout(() => pollScan(scanId), 1000);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;

  const values = readForm();
  const problem = validate(values);
  if (problem) {
    showError(problem);
    return;
  }

  startButton.disabled = true;
  startButton.textContent = "Starting…";
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(values),
    });
    const result = await response.json();
    if (!response.ok) {
      showError(result.error || "The scan could not be started.");
      startButton.disabled = false;
      startButton.textContent = "Start scan";
      return;
    }
    form.hidden = true;
    progressCard.hidden = false;
    document.getElementById("progress-target").textContent = result.target_url;
    pollScan(result.scan_id);
  } catch (error) {
    showError("Could not reach the server. Is app.py still running?");
    startButton.disabled = false;
    startButton.textContent = "Start scan";
  }
});
