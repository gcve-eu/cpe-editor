// Member picker of the alias forms. Searching and changing page reload the
// form, keeping typed values and checked products. The selected list follows the
// checkboxes and collapses when it gets long.
const form = document.querySelector("form[data-member-picker]");
const list = document.getElementById("selected-members");
const empty = document.getElementById("selected-members-empty");

// Posted rather than sent in the URL: a large selection would exceed URL limits.
// The "refresh" field tells the server to render the form without saving.
function reload(page) {
  const url = new URL(location.href);
  // The search is posted: an old one in the URL would take precedence over it.
  url.searchParams.delete("q");
  url.searchParams.delete("product_ids");
  url.searchParams.delete("page");
  if (page) url.searchParams.set("page", page);
  url.hash = "find-products";
  const refresh = document.createElement("input");
  refresh.type = "hidden";
  refresh.name = "refresh";
  refresh.value = "1";
  form.append(refresh);
  form.action = url;
  form.noValidate = true;
  form.submit();
}

document.getElementById("alias-product-search").addEventListener("click", () => reload());

// Reset is active as soon as there is a search to clear, typed or already applied.
const search = document.getElementById("q");
const reset = document.getElementById("alias-product-reset");
const updateReset = () => { reset.disabled = !search.value.trim() && !reset.dataset.applied; };
search.addEventListener("input", updateReset);
reset.addEventListener("click", () => {
  search.value = "";
  if (reset.dataset.applied) reload();
  else updateReset();
  search.focus();
});
updateReset();
document.getElementById("q").addEventListener("keydown", event => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  reload();
});
form.addEventListener("click", event => {
  const link = event.target.closest?.(".pagination a");
  if (!link) return;
  event.preventDefault();
  reload(new URL(link.href).searchParams.get("page"));
});

const COLLAPSE_ABOVE = 199;
const STEP = 100;
const count = document.getElementById("selected-members-count");
const actions = document.getElementById("selected-members-actions");
const more = document.getElementById("selected-members-more");
const collapse = document.getElementById("selected-members-collapse");
let shown = STEP;

function refresh() {
  const items = [...list.children];
  const total = items.length;
  list.hidden = !total;
  empty.hidden = Boolean(total);
  const limit = Number(count.dataset.limit);
  count.textContent = total > limit
    ? `${total.toLocaleString()} selected: remove ${(total - limit).toLocaleString()} to save (maximum ${limit.toLocaleString()})`
    : total ? `${total.toLocaleString()} of ${limit.toLocaleString()} maximum selected` : "";
  count.classList.toggle("is-error", total > limit);
  const collapsible = total > COLLAPSE_ABOVE;
  if (!collapsible) shown = STEP;
  items.forEach((item, index) => { item.hidden = collapsible && index >= shown; });
  actions.hidden = !collapsible;
  const left = total - shown;
  more.hidden = left <= 0;
  more.textContent = `Show ${Math.min(STEP, left)} more (${left.toLocaleString()} hidden)`;
  collapse.hidden = shown <= STEP;
  updateSubmit();
}

// Saving stays disabled until the alias has a name and an allowed number of members.
function updateSubmit() {
  const total = list.children.length;
  const ready = form.querySelector("input[required]").value.trim() && total && total <= Number(count.dataset.limit);
  const reason = !total ? "Select at least one product." : "Fill in the required fields.";
  document.querySelectorAll(`button[type="submit"][form="${form.id}"], #${form.id} button[type="submit"]`).forEach(button => {
    button.disabled = !ready;
    button.title = ready ? "" : reason;
  });
}
form.querySelector("input[required]").addEventListener("input", updateSubmit);

more.addEventListener("click", () => { shown += STEP; refresh(); });
collapse.addEventListener("click", () => { shown = STEP; refresh(); });

function addMember(id, text) {
  if (list.querySelector(`[data-product-id="${CSS.escape(id)}"]`)) return;
  const item = document.createElement("li");
  item.className = "active-filter";
  item.dataset.productId = id;
  const label = document.createElement("span");
  label.textContent = text;
  const remove = document.createElement("button");
  remove.type = "button";
  remove.textContent = "×";
  remove.setAttribute("aria-label", "Remove member");
  item.append(label, remove);
  list.append(item);
}

form.addEventListener("change", event => {
  const box = event.target;
  if (!box.matches?.('input[type="checkbox"][name="product_ids"]')) return;
  if (box.checked) addMember(box.value, box.dataset.memberLabel);
  else list.querySelector(`[data-product-id="${CSS.escape(box.value)}"]`)?.remove();
  refresh();
});

list.addEventListener("click", event => {
  if (!event.target.closest("button")) return;
  const item = event.target.closest("li");
  const id = item.dataset.productId;
  form.querySelectorAll('input[name="product_ids"]').forEach(input => {
    if (input.value !== id) return;
    if (input.type === "checkbox") input.checked = false;
    else input.remove();
  });
  item.remove();
  refresh();
});

// Vitrine's row checkboxes drive the hidden form checkboxes of the same rows. Its
// header checkbox therefore selects the products of the current page.
const boxes = [...form.querySelectorAll('input[type="checkbox"][name="product_ids"]')];
const waitForTable = setInterval(() => {
  const host = document.querySelector("#find-products application-table");
  if (!host?.selected) return;
  clearInterval(waitForTable);
  host.addEventListener("vt-select", event => {
    const keys = new Set(event.detail.keys);
    boxes.forEach((box, index) => {
      const wanted = keys.has(String(index));
      if (box.checked === wanted) return;
      box.checked = wanted;
      if (wanted) addMember(box.value, box.dataset.memberLabel);
      else list.querySelector(`[data-product-id="${CSS.escape(box.value)}"]`)?.remove();
    });
    refresh();
  });
  host.select(boxes.flatMap((box, index) => box.checked ? [String(index)] : []));
  list.addEventListener("click", () => {
    host.select(boxes.flatMap((box, index) => box.checked ? [String(index)] : []));
  });
}, 50);
setTimeout(() => clearInterval(waitForTable), 10000);

form.addEventListener("submit", event => {
  if (list.children.length > Number(count.dataset.limit)) {
    event.preventDefault();
    count.scrollIntoView({block: "center"});
    return;
  }
  if (list.children.length) return;
  event.preventDefault();
  empty.querySelector(".empty-state-title").textContent = "Select at least one product";
  empty.querySelector(".empty-state-title").classList.add("is-error");
  empty.scrollIntoView({block: "center"});
});

refresh();
