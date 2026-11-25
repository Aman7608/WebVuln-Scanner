// WebVuln Test Lab - small helpers: search + filter on the home page, copy buttons.
// (No addresses are written in this file on purpose: the scanner reads .js files
// to find API paths, and this file should not add any fake ones.)

(function () {
  // ----- copy buttons: <button data-copy="text"> -----
  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var text = button.getAttribute("data-copy");
      var done = function () {
        var old = button.textContent;
        button.textContent = "Copied!";
        setTimeout(function () { button.textContent = old; }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        done();
      }
    });
  });

  // ----- home page: filter chips and search box -----
  var cards = Array.prototype.slice.call(document.querySelectorAll(".lab-card"));
  if (!cards.length) return;
  var search = document.getElementById("lab-search");
  var chips = Array.prototype.slice.call(document.querySelectorAll(".chip"));
  var counter = document.getElementById("lab-count");
  var empty = document.getElementById("lab-empty");
  var filter = "all";

  function update() {
    var words = (search.value || "").toLowerCase().trim();
    var shown = 0;
    cards.forEach(function (card) {
      var kindOk = filter === "all" || card.getAttribute("data-kind") === filter;
      var textOk = !words || card.textContent.toLowerCase().indexOf(words) !== -1;
      card.hidden = !(kindOk && textOk);
      if (!card.hidden) shown += 1;
    });
    counter.textContent = shown + " of " + cards.length + " pages";
    empty.hidden = shown !== 0;
  }

  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      chips.forEach(function (c) { c.classList.remove("active"); });
      chip.classList.add("active");
      filter = chip.getAttribute("data-filter");
      update();
    });
  });
  search.addEventListener("input", update);

  // Press "/" anywhere to jump to the search box
  document.addEventListener("keydown", function (event) {
    if (event.key === "/" && document.activeElement !== search) {
      event.preventDefault();
      search.focus();
    }
  });
  update();
})();
