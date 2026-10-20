(() => {
  let assets;

  function loadAssets(panel) {
    if (!assets) {
      assets = Promise.all([
        ["link", "href", panel.dataset.stylesUrl],
        ["script", "src", panel.dataset.libraryUrl],
      ].map(([tag, attribute, url]) => new Promise((resolve, reject) => {
        const element = document.createElement(tag);
        if (tag === "link") element.rel = "stylesheet";
        element[attribute] = url;
        element.onload = resolve;
        element.onerror = () => { element.remove(); reject(new Error("Graph asset failed to load")); };
        document.head.appendChild(element);
      }))).catch((error) => { assets = null; throw error; });
    }
    return assets;
  }

  document.querySelectorAll(".entity-graph").forEach((panel) => {
    const status = panel.querySelector(".graph-status");
    const retry = panel.querySelector(".graph-retry");
    const content = panel.querySelector(".graph-content");
    const canvas = panel.querySelector(".graph-canvas");
    const picker = panel.querySelector(".graph-record-picker");
    const selection = panel.querySelector(".graph-selection");
    const simplify = panel.querySelector(".graph-simplify");
    let graph;
    let payload;
    let loading = false;

    function setupSimplification() {
      const rules = panel.querySelector(".graph-simplify-rules");
      rules.replaceChildren();
      const controls = graph.simplify.getRules().map((rule) => {
        const fieldset = document.createElement("fieldset");
        const legend = document.createElement("legend");
        const label = document.createElement("label");
        const toggle = document.createElement("input");
        toggle.type = "checkbox";
        toggle.checked = rule.enabled;
        toggle.addEventListener("change", () => graph.simplify.setRuleEnabled(rule.id, toggle.checked));
        label.append(toggle, ` ${rule.label}`);
        legend.append(label);
        const description = document.createElement("p");
        description.textContent = rule.description;
        const settingLabel = document.createElement("label");
        const setting = document.createElement("input");
        setting.type = "number";
        setting.min = rule.setting.min;
        setting.max = rule.setting.max;
        setting.step = 1;
        setting.value = rule.setting.value;
        setting.addEventListener("change", () => {
          if (setting.value && setting.checkValidity()) {
            graph.simplify.setRuleSetting(rule.id, setting.valueAsNumber);
          }
          setting.value = graph.simplify.getRules().find((current) => current.id === rule.id).setting.value;
        });
        settingLabel.append(`${rule.setting.label} `, setting);
        fieldset.append(legend, description, settingLabel);
        rules.append(fieldset);
        return { id: rule.id, toggle };
      });
      function syncSimplification() {
        graph.simplify.getRules().forEach((rule) => {
          controls.find((control) => control.id === rule.id).toggle.checked = rule.enabled;
        });
        const { shown, total, groups, folded } = graph.simplify.summary();
        panel.querySelector(".graph-simplify-status").textContent = `${shown} shown of ${total} records · ${groups} groups · ${folded} folded.`;
      }
      graph.simplify.onChange(syncSimplification);
      syncSimplification();
    }

    function inspect(data) {
      selection.replaceChildren();
      const label = document.createElement("strong");
      label.textContent = data.label;
      selection.append(label, document.createElement("br"));
      if (data.url) {
        selection.append(`${data.kind.toUpperCase()} · ${data.detail}`, document.createElement("br"));
        const link = document.createElement("a");
        link.href = data.url;
        link.textContent = "Open record";
        selection.append(link);
      } else if (data.rationale) {
        selection.append(data.rationale);
      }
    }

    function syncTheme() {
      canvas.querySelector(".pivotick")?.setAttribute("data-theme", document.documentElement.dataset.theme || "light");
    }

    async function load() {
      if (graph || loading || !panel.open) return;
      loading = true;
      retry.hidden = true;
      status.textContent = "Loading relationship graph…";
      try {
        const [response] = await Promise.all([
          fetch(panel.dataset.graphUrl, { headers: { Accept: "application/json" } }),
          loadAssets(panel),
        ]);
        if (!response.ok) throw new Error(`Graph request failed: ${response.status}`);
        payload = await response.json();
        // A panel closed while loading is rendered on its next expansion.
        if (!panel.open) { status.textContent = ""; return; }
        content.hidden = false;
        graph = new window.Pivotick(canvas, {
          nodes: payload.nodes.map((node) => ({
            ...node,
            style: node.data.current ? { strokeColor: "var(--text)", strokeWidth: 4, size: 22 } : {},
          })),
          edges: payload.edges.map((edge) => ({
            ...edge,
            style: { edge: { dashed: edge.data.kind === "contains" } },
          })),
        }, {
          isDirected: true,
          UI: {
            mode: "viewer", theme: document.documentElement.dataset.theme || "light", navigation: { enabled: false },
            // Keep rules off until the user chooses how to simplify this view.
            simplify: {
              rules: ["neighbours", "chains", "degree", "kcore"].map((kind) => ({ kind, enabled: false })),
            },
          },
          simulation: {
            useWorker: true,
            // Keep the fallback short if browser policy prevents worker creation.
            // Pivotick also runs a cooling stage after its warmup ticks.
            warmupTicks: 1, cooldownTime: 250, d3AlphaDecay: 0.2,
            d3LinkDistance: 150, d3ManyBodyStrength: -600,
          },
          render: {
            nodeTypeAccessor: (node) => node.getData().kind,
            nodeStyleMap: {
              alias: { shape: { d: "M 0 -22 L 22 0 L 0 22 L -22 0 Z" }, color: "#be185d" },
              vendor: { shape: "square", color: "#0a6e6f" },
              product: { shape: "circle", color: "#6366f1" },
              cpe: { shape: "hexagon", color: "#b45309" },
            },
            defaultNodeStyle: {
              size: 16,
              text: (node) => {
                const label = node.getData().label;
                return label.length > 36 ? `${label.slice(0, 35)}…` : label;
              },
              textColor: "var(--text)", textVerticalShift: -1.8, textTruncate: false,
              strokeColor: "var(--card-bg)",
            },
            defaultEdgeStyle: { strokeColor: "var(--muted)", markerEnd: "arrow" },
            // Native SVG text avoids zero-sized HTML label containers during layout.
            defaultLabelStyle: {
              fontSize: 12, fontFamily: "var(--font-sans)",
              color: "var(--text)", backgroundColor: "var(--card-bg)",
            },
          },
          callbacks: {
            onNodeClick: (_, node) => {
              picker.value = node.isGroup ? "" : node.id;
              inspect(node.isGroup ? {
                label: graph.simplify.labelOf(node.info),
                rationale: `${node.info.members.length} records in this group. Double-click the group to show its members, or use the record picker to inspect an individual record.`,
              } : node.getData());
            },
            onEdgeClick: (_, edge) => {
              picker.value = "";
              inspect(edge.isSynthetic && edge.representedEdges.length > 1 ? {
                label: `${edge.representedEdges.length} links`,
                rationale: "These links connect grouped records. Open the groups to inspect the individual links.",
              } : edge.getData());
            },
          },
        });
        setupSimplification();
        syncTheme();
        picker.replaceChildren(new Option("Choose a record", ""));
        payload.nodes.forEach((node) => picker.add(new Option(`${node.data.kind.toUpperCase()} · ${node.data.label}`, node.id)));
        picker.value = payload.root;
        inspect(payload.nodes.find((node) => node.id === payload.root).data);
        graph.renderer.fitAndCenterWhenSettled();
        status.textContent = `${payload.nodes.length} records · ${payload.edges.length} links.`;
        if (payload.truncated) {
          status.textContent += ` This graph is limited to ${payload.limits.nodes} records and ${payload.limits.edges} links. Explore a linked record for more; the lists below remain available.`;
        }
      } catch (error) {
        console.error("Unable to load relationship graph", error);
        graph?.destroy();
        graph = null;
        canvas.replaceChildren();
        content.hidden = true;
        status.textContent = "The graph could not load. You can retry or use the record lists below.";
        retry.hidden = false;
      } finally {
        loading = false;
      }
    }

    panel.addEventListener("toggle", () => {
      if (panel.open) {
        if (graph) graph.renderer.fitAndCenterWhenSettled();
        else load();
      }
    });
    retry.addEventListener("click", load);
    simplify.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        simplify.open = false;
        simplify.querySelector("summary").focus();
        event.stopPropagation();
      }
    });
    document.addEventListener("click", (event) => {
      if (!simplify.contains(event.target)) simplify.open = false;
    });
    picker.addEventListener("change", () => {
      const node = payload.nodes.find((node) => node.id === picker.value);
      if (node) inspect(node.data);
      else selection.replaceChildren();
    });
    panel.querySelectorAll("[data-graph-action]").forEach((button) => {
      button.addEventListener("click", () => {
        if (!graph) return;
        const action = button.dataset.graphAction;
        if (action === "fit") graph.renderer.fitAndCenter();
        else if (action === "in") graph.renderer.zoomIn();
        else graph.renderer.zoomOut();
      });
    });
    new MutationObserver(syncTheme).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    new ResizeObserver(() => {
      if (graph && panel.open && canvas.clientWidth) graph.renderer.fitAndCenterWhenSettled();
    }).observe(canvas);
    window.addEventListener("pagehide", () => {
      simplify.open = false;
      graph?.destroy();
      graph = null;
      canvas.replaceChildren();
      content.hidden = true;
    });
    window.addEventListener("pageshow", () => { if (panel.open) load(); });
    if (panel.open) load();
  });
})();
