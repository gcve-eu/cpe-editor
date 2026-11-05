// Edit a [data-markdown-editor] textarea in <vt-markdown>. The textarea keeps the
// submitted value and stays visible if the component cannot load.
const FORMATS = [
  {label: "Bold", icon: "bold", before: "**", after: "**", sample: "bold text"},
  {label: "Italic", icon: "italic", before: "*", after: "*", sample: "italic text"},
  {label: "Inline code", icon: "code", before: "`", after: "`", sample: "code"},
  {label: "Link", icon: "link", before: "[", after: "](https://)", sample: "link text"},
  {label: "Heading", icon: "heading", line: "## ", sample: "Heading"},
  {label: "Bulleted list", icon: "list-ul", line: "- ", sample: "List item"},
  {label: "Numbered list", icon: "list-ol", line: "1. ", sample: "List item"},
  {label: "Quote", icon: "quote-left", line: "> ", sample: "Quote"},
];

// Vitrine has no formatting buttons: these write Markdown into its editor.
function applyFormat(area, format) {
  const {selectionStart: start, selectionEnd: end, value} = area;
  const selected = value.slice(start, end) || format.sample;
  let text;
  if (format.line) {
    const atLineStart = start === 0 || value[start - 1] === "\n";
    text = (atLineStart ? "" : "\n") + selected.split("\n").map(line => format.line + line).join("\n");
  } else {
    text = format.before + selected + format.after;
  }
  area.focus();
  area.setRangeText(text, start, end, "end");
  area.dispatchEvent(new Event("input", {bubbles: true}));
}

function formatBar(editor) {
  const bar = document.createElement("div");
  bar.className = "markdown-format-bar";
  bar.setAttribute("role", "toolbar");
  bar.setAttribute("aria-label", "Markdown formatting");
  FORMATS.forEach(format => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary icon-button";
    button.title = format.label;
    button.setAttribute("aria-label", format.label);
    const icon = document.createElement("i");
    icon.className = `fa-solid fa-${format.icon}`;
    icon.setAttribute("aria-hidden", "true");
    button.append(icon);
    button.addEventListener("click", async () => {
      if (!editor.shadowRoot.querySelector("textarea")) {
        [...editor.shadowRoot.querySelectorAll('[role="tab"]')].find(tab => tab.textContent.trim() === "Split")?.click();
        await new Promise(requestAnimationFrame);
      }
      const area = editor.shadowRoot.querySelector("textarea");
      if (area) applyFormat(area, format);
    });
    bar.append(button);
  });
  return bar;
}

const fields = [...document.querySelectorAll("textarea[data-markdown-editor]")];
if (fields.length) {
  try {
    await import("../vendor/vitrine/content/esm/vt-markdown.js");
    fields.forEach(field => {
      const editor = document.createElement("vt-markdown");
      editor.dataset.vitrineViewer = "";
      editor.setAttribute("theme", document.documentElement.dataset.theme || "auto");
      editor.setAttribute("variant", "full");
      editor.setAttribute("mode", "edit");
      editor.setAttribute("images", "block");
      editor.setAttribute("allow-html", "false");
      editor.setAttribute("download", "false");
      editor.setAttribute("label", field.dataset.markdownEditor);
      if (field.placeholder) editor.setAttribute("placeholder", field.placeholder);
      editor.content = field.value;
      editor.addEventListener("vt-input", event => {
        field.value = event.detail.value;
        field.dispatchEvent(new Event("input", {bubbles: true}));
      });
      editor.addEventListener("vt-error", () => {
        editor.remove();
        field.hidden = false;
      });
      // The file name and the field label both lead to the writing area.
      const focusEditor = async () => {
        if (!editor.shadowRoot.querySelector("textarea")) {
          [...editor.shadowRoot.querySelectorAll('[role="tab"]')].find(tab => tab.textContent.trim() === "Split")?.click();
          await new Promise(requestAnimationFrame);
        }
        editor.shadowRoot.querySelector("textarea")?.focus();
      };
      editor.shadowRoot.addEventListener("click", event => {
        if (event.target.closest?.(".title, .dot")) focusEditor();
      });
      field.labels?.forEach(label => label.addEventListener("click", event => {
        event.preventDefault();
        focusEditor();
      }));
      field.hidden = true;
      field.after(editor);
      const bar = formatBar(editor);
      editor.before(bar);
      // The editor can apply to one value of another field; otherwise it is plain text.
      const condition = document.getElementById(field.dataset.markdownWhenId);
      if (condition) {
        const update = () => {
          const markdown = condition.value === field.dataset.markdownWhenValue;
          if (markdown) editor.content = field.value;
          editor.hidden = !markdown;
          bar.hidden = !markdown;
          field.hidden = markdown;
        };
        condition.addEventListener("change", update);
        update();
      }
    });
  } catch (_) {
    // The native textarea stays available.
  }
}
