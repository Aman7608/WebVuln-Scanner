// Cancel button for a running scan (used on the New Scan and Results pages).
// The scan stops before its next request and keeps what it found so far.

function setupCancelButton(getScanId) {
  const button = document.getElementById("cancel-button");
  if (!button) return;

  button.addEventListener("click", async () => {
    const scanId = getScanId();
    if (!scanId) return;
    if (!window.confirm("Stop this scan? Findings so far will be kept.")) return;

    button.disabled = true;
    button.textContent = "Cancelling…";
    try {
      const response = await postJson(`/api/scans/${scanId}/cancel`);   // from common.js
      if (!response.ok) {
        const result = await response.json();
        button.textContent = result.error || "Could not cancel";
      }
      // The progress polling notices the new status and moves to the results page
    } catch (error) {
      button.disabled = false;
      button.textContent = "Cancel scan";
    }
  });
}
