// Edit the admin ingest payload in <vt-json>. The native textarea stays the
// submitted value and remains visible if the component cannot load.
const form = document.getElementById("json_ingest_form");
const field = document.getElementById("json_payload");
const error = document.getElementById("json_payload_error");

function showError(message) {
  error.textContent = message;
  error.hidden = !message;
}

try {
  await import("../vendor/vitrine/content/esm/vt-json.js");
  const editor = document.createElement("vt-json");
  // Vitrine reports an empty editor as invalid JSON: hide that status.
  const markEmpty = () => editor.toggleAttribute("data-empty", !field.value.trim());
  editor.dataset.vitrineViewer = "";
  editor.setAttribute("theme", document.documentElement.dataset.theme || "auto");
  editor.setAttribute("variant", "full");
  editor.setAttribute("mode", "edit");
  editor.setAttribute("tabs", "");
  editor.setAttribute("label", "payload.json");
  editor.setAttribute("placeholder", field.placeholder);
  editor.addEventListener("vt-input", event => {
    field.value = event.detail.value;
    markEmpty();
    showError("");
  });
  editor.addEventListener("vt-error", () => {
    editor.remove();
    field.hidden = false;
    field.required = true;
  });
  // A hidden required field would silently block the submit.
  field.required = false;
  field.hidden = true;
  markEmpty();
  editor.content = field.value;
  field.after(editor);
  if (!error.hidden) form.scrollIntoView({block: "center"});

  form.addEventListener("submit", event => {
    // An empty payload is not an error: nothing to send, nothing to report.
    if (!field.value.trim()) {
      event.preventDefault();
      showError("");
    } else if (editor.data === undefined) {
      event.preventDefault();
      showError("Invalid JSON: fix the payload before ingesting.");
    }
  });
} catch (_) {
  field.hidden = false;
  field.required = true;
}
