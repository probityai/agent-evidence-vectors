/* Filter a complete static projection. Never score or alter a retained record. */
(() => {
  "use strict";
  const form = document.getElementById("run-filters");
  const root = document.getElementById("run-records");
  if (!form || !root) return;
  const search = document.getElementById("run-search");
  const result = document.getElementById("run-result");
  const count = document.getElementById("run-count");
  const empty = document.getElementById("run-empty");
  const records = Array.from(root.querySelectorAll(".run-record")).map(record => {
    const heading = record.querySelector("h2");
    const searchable = record.textContent.toLowerCase();
    const tokens = new Set(record.dataset.results.split(" "));
    const disclosure = document.createElement("details");
    disclosure.className = "run-disclosure";
    const summary = document.createElement("summary");
    record.before(disclosure);
    summary.append(heading);
    disclosure.append(summary, record);
    return { disclosure, searchable, tokens };
  });
  function update() {
    const query = search.value.trim().toLowerCase();
    let visible = 0;
    for (const record of records) {
      const match = record.searchable.includes(query) && (!result.value || record.tokens.has(result.value));
      record.disclosure.hidden = !match;
      if (match) visible += 1;
    }
    count.textContent = `Showing ${visible} of ${records.length} retained records. Results belong to individual claims.`;
    empty.hidden = visible !== 0;
  }
  form.addEventListener("submit", event => event.preventDefault());
  form.addEventListener("input", update);
  form.addEventListener("change", update);
  form.addEventListener("reset", () => {
    search.value = "";
    result.value = "";
    update();
  });
  function revealHash() {
    let fragment;
    try { fragment = decodeURIComponent(location.hash.slice(1)); }
    catch { return; }
    const target = document.getElementById(fragment);
    const disclosure = target?.closest(".run-disclosure");
    if (!disclosure) return;
    if (disclosure.hidden) {
      search.value = "";
      result.value = "";
      update();
    }
    disclosure.open = true;
    target.scrollIntoView({ block: "start" });
  }
  form.hidden = false;
  update();
  revealHash();
  window.addEventListener("hashchange", revealHash);
})();
