// Replace the list of a <select> inside a form field with one styled like the
// site. The native select stays in the form, holds the value and is what gets
// submitted; without JavaScript it is simply shown as is.
(() => {
  "use strict";
  let count = 0;

  function enhance(select) {
    // Search pickers rewrite their options and show them as a native list.
    if (select.multiple || select.classList.contains("suggestion-picker")) return;
    const label = document.querySelector(`label[for="${CSS.escape(select.id)}"]`);
    const uid = `site-select-${++count}`;
    const button = document.createElement("button");
    button.type = "button";
    button.id = `${uid}-button`;
    button.className = "site-select-button";
    button.setAttribute("role", "combobox");
    button.setAttribute("aria-haspopup", "listbox");
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-controls", `${uid}-list`);
    const text = document.createElement("span");
    const chevron = document.createElement("i");
    chevron.className = "fa-solid fa-chevron-down";
    chevron.setAttribute("aria-hidden", "true");
    button.append(text, chevron);

    const list = document.createElement("ul");
    list.id = `${uid}-list`;
    list.className = "site-select-list";
    list.setAttribute("role", "listbox");
    list.hidden = true;
    if (label) {
      if (!label.id) label.id = `${uid}-label`;
      button.setAttribute("aria-labelledby", `${label.id} ${button.id}`);
      list.setAttribute("aria-labelledby", label.id);
      label.htmlFor = button.id;
    }

    const items = [...select.options].map((option, index) => {
      const item = document.createElement("li");
      item.id = `${uid}-option-${index}`;
      item.setAttribute("role", "option");
      item.textContent = option.textContent;
      item.addEventListener("mousedown", event => event.preventDefault());
      item.addEventListener("click", () => { choose(index); close(); });
      item.addEventListener("mousemove", () => setActive(index));
      list.append(item);
      return item;
    });

    let active = -1;
    function setActive(index) {
      items[active]?.classList.remove("active");
      active = index;
      items[active]?.classList.add("active");
      items[active]?.scrollIntoView({block: "nearest"});
      if (active >= 0) button.setAttribute("aria-activedescendant", items[active].id);
      else button.removeAttribute("aria-activedescendant");
    }
    function sync() {
      text.textContent = select.selectedOptions[0]?.textContent || "";
      items.forEach((item, index) => item.setAttribute("aria-selected", String(index === select.selectedIndex)));
    }
    function choose(index) {
      if (select.options[index].disabled) return;
      if (index !== select.selectedIndex) {
        select.selectedIndex = index;
        select.dispatchEvent(new Event("input", {bubbles: true}));
        select.dispatchEvent(new Event("change", {bubbles: true}));
      }
      sync();
    }
    function open() {
      list.hidden = false;
      button.setAttribute("aria-expanded", "true");
      setActive(select.selectedIndex);
    }
    function close() {
      list.hidden = true;
      button.setAttribute("aria-expanded", "false");
      setActive(-1);
    }

    button.addEventListener("click", () => (list.hidden ? open() : close()));
    button.addEventListener("blur", close);
    button.addEventListener("keydown", event => {
      const last = items.length - 1;
      const moves = {ArrowDown: Math.min(active + 1, last), ArrowUp: Math.max(active - 1, 0), Home: 0, End: last};
      if (event.key in moves) {
        event.preventDefault();
        if (list.hidden) open();
        else setActive(moves[event.key]);
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        if (list.hidden) open();
        else { choose(active); close(); }
      } else if (event.key === "Escape" && !list.hidden) {
        event.preventDefault();
        close();
      } else if (event.key === "Tab" && !list.hidden) {
        close();
      } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
        const match = items.findIndex(item => item.textContent.trim().toLowerCase().startsWith(event.key.toLowerCase()));
        if (match >= 0) { if (list.hidden) choose(match); else setActive(match); }
      }
    });
    select.addEventListener("change", sync);
    select.form?.addEventListener("reset", () => setTimeout(sync));

    select.classList.add("site-select-native");
    select.tabIndex = -1;
    select.setAttribute("aria-hidden", "true");
    select.after(button, list);
    sync();
  }

  document.querySelectorAll(".field-control select").forEach(enhance);
})();
