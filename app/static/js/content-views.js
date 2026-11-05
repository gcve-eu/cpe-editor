(() => {
  "use strict";
  const script = document.currentScript;
  const modules = new Map();
  const kinds = new Set(["code", "json", "markdown", "diff", "chart"]);
  const roots = [...document.querySelectorAll("[data-vitrine-kind]")];
  const theme = () => document.documentElement.dataset.theme || "auto";

  function loadModule(kind) {
    if (!modules.has(kind)) modules.set(kind, kind === "chart"
      ? Promise.all([import(new URL("statistics-chart.js", script.src).href),
        import(new URL("../vendor/vitrine/content/vendor/echarts.js", script.src).href)])
      : import(new URL(`../vendor/vitrine/content/esm/vt-${kind}.js`, script.src).href));
    return modules.get(kind);
  }

  function source(root) {
    if (root.dataset.vitrineInput) return document.getElementById(root.dataset.vitrineInput).value;
    if (root.dataset.vitrineKind === "chart") return JSON.stringify([...root.querySelectorAll("[data-chart-label]")].map(row => ({
      Label: row.dataset.chartLabel + (row.dataset.chartDetail ? ` (${row.dataset.chartDetail})` : ""), Value: Number(row.dataset.chartValue)
    })));
    const value = root.querySelector("script[data-vitrine-value]");
    return value ? JSON.parse(value.textContent) : "";
  }

  async function enhance(root) {
    const kind = root.dataset.vitrineKind;
    if (!kinds.has(kind) || root.dataset.loading || root.dataset.loaded || root.hidden) return;
    root.dataset.loading = "true";
    const status = root.querySelector(".vitrine-status");
    const fallback = root.querySelector("[data-vitrine-fallback]");
    let viewer;
    function failed() {
      root.dataset.loaded = "";
      fallback.hidden = false;
      viewer?.remove();
      status.textContent = "The enhanced view could not load. The original content remains available.";
    }
    try {
      status.textContent = "Loading view…";
      const [, value] = await Promise.all([loadModule(kind), root.dataset.vitrineUrl ? (async () => {
        const url = new URL(root.dataset.vitrineUrl, location.href);
        if (url.origin !== location.origin) throw new Error("Invalid record URL");
        const response = await fetch(url, {headers: {Accept: "application/json"}, credentials: "same-origin"});
        if (!response.ok) throw new Error("Record unavailable");
        return response.text();
      })() : Promise.resolve(source(root))]);
      viewer = document.createElement(kind === "chart" ? "editor-chart" : `vt-${kind}`);
      viewer.dataset.vitrineViewer = "";
      viewer.setAttribute("variant", "full");
      viewer.setAttribute("theme", theme());
      const label = root.dataset.vitrineLabel || root.closest("section, .card")?.querySelector("h2")?.textContent.trim() || "Preview";
      viewer.setAttribute("label", label);
      viewer.setAttribute("wrap", "true");
      if (root.dataset.vitrineFilename) viewer.setAttribute("download", root.dataset.vitrineFilename);
      if (kind === "markdown") {
        viewer.setAttribute("images", "block");
        viewer.setAttribute("allow-html", "false");
      }
      if (kind === "code") { viewer.setAttribute("language", "plaintext"); viewer.setAttribute("line-numbers", "false"); }
      if (kind === "json") viewer.setAttribute("on-invalid", "raw");
      if (kind === "diff") {
        viewer.setAttribute("language", "json");
        viewer.setAttribute("view", "unified");
        viewer.setAttribute("original-label", "current.json");
        viewer.setAttribute("modified-label", "proposed.json");
      }
      if (kind === "chart") {
        viewer.setAttribute("download", `${label.toLowerCase().replace(/[^a-z0-9]+/g, "-") || "chart"}.csv`);
        viewer.setAttribute("type", "bar");
        viewer.setAttribute("horizontal", "true");
        viewer.setAttribute("height", String(Math.max(240, Math.min(800, JSON.parse(value).length * 32 + 70))));
        if (root.dataset.vitrineUnit) viewer.setAttribute("unit", root.dataset.vitrineUnit);
      }
      viewer.addEventListener("vt-ready", () => {
        fallback.hidden = true;
        viewer.hidden = false;
        status.textContent = "";
        root.dataset.loaded = "true";
      });
      viewer.addEventListener("vt-error", event => {
        // An invalid JSON preview should show its error/raw text while the
        // native input stays editable. Other failures restore the fallback.
        if (kind === "json" && root.dataset.vitrineInput) {
          fallback.hidden = true;
          viewer.hidden = false;
          status.textContent = "";
          root.dataset.loaded = "true";
        } else queueMicrotask(failed);
      });
      const update = () => {
        const current = root.dataset.vitrineInput ? source(root) : value;
        if (kind === "diff") { viewer.original = current.original; viewer.modified = current.modified; }
        else viewer.content = current;
      };
      root.updateVitrine = update;
      update();
      viewer.hidden = true;
      root.append(viewer);
      if (root.dataset.vitrineInput && !root.dataset.bound) {
        let timer;
        document.getElementById(root.dataset.vitrineInput).addEventListener("input", () => {
          clearTimeout(timer);
          timer = setTimeout(() => { if (root.dataset.loaded) root.updateVitrine(); }, 120);
        });
        root.dataset.bound = "true";
      }
    } catch (_) { failed(); }
    finally { delete root.dataset.loading; }
  }

  const observer = new IntersectionObserver(entries => entries.forEach(entry => {
    if (entry.isIntersecting) { observer.unobserve(entry.target); enhance(entry.target); }
  }), {rootMargin: "120px"});
  roots.forEach(root => {
    if (root.dataset.vitrineCondition) {
      const input = document.getElementById(root.dataset.vitrineCondition);
      const update = () => { root.hidden = input.value !== "gcve:description"; if (root.open && !root.hidden) enhance(root); };
      input.addEventListener("change", update);
      update();
    }
    if (root.tagName === "DETAILS") root.addEventListener("toggle", () => { if (root.open) enhance(root); });
    else observer.observe(root);
  });
  new MutationObserver(() => document.querySelectorAll("[data-vitrine-viewer]").forEach(viewer => viewer.setAttribute("theme", theme())))
    .observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
})();
