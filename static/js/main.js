// Small helpers for the Dashboard and Results pages.

// 1. Severity distribution bar: set each segment's width from its count
const segments = document.querySelectorAll(".dist-seg");
const total = Array.from(segments).reduce((sum, seg) => sum + Number(seg.dataset.share), 0);
segments.forEach((seg) => {
  seg.style.width = (Number(seg.dataset.share) / total) * 100 + "%";
});

// 2. Severity filter buttons on the Results page
const filterButtons = document.querySelectorAll("#severity-filters .chip");
filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    filterButtons.forEach((b) => b.classList.remove("active"));
    button.classList.add("active");
    const filter = button.dataset.filter;
    document.querySelectorAll(".finding").forEach((finding) => {
      finding.hidden = filter !== "all" && finding.dataset.severity !== filter;
    });
  });
});

// 3. Live progress when a Results page is opened while the scan is running
const live = document.getElementById("live-progress");
if (live) {
  const fill = document.getElementById("progress-fill");
  fill.style.width = fill.dataset.progress + "%";

  const scanId = live.dataset.scanId;
  const poll = async () => {
    try {
      const scan = await (await fetch(`/api/scans/${scanId}`)).json();
      fill.style.width = scan.progress + "%";
      document.getElementById("progress-percent").textContent = scan.progress + "%";
      document.getElementById("progress-step").textContent = scan.current_step || "Starting…";
      if (scan.status === "completed" || scan.status === "failed") {
        window.location.reload();
        return;
      }
    } catch (error) {
      // try again next time
    }
    setTimeout(poll, 1000);
  };
  setTimeout(poll, 1000);
}
