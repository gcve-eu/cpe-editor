// Search forms of the _ui.html components: refuse a search with nothing to look
// for, unless the form allows it to clear an active search (data-allow-empty).
document.querySelectorAll(".search-form").forEach(form => {
  const submit = form.querySelector(".search-submit");
  const message = form.querySelector(".search-empty-message");
  if (!submit || !message) return;
  const emptyText = "Enter at least one character in a filter.";
  let messageTimer;
  const isBlocked = () => !form.dataset.allowEmpty
    && ![...form.querySelectorAll("input[name]:not([type=hidden]), select[name]")].some(control => control.value.trim());
  const update = () => {
    const blocked = isBlocked();
    submit.classList.toggle("is-empty", blocked);
    submit.title = blocked ? emptyText : "";
    if (!blocked) message.hidden = true;
  };
  form.addEventListener("input", update);
  form.addEventListener("change", update);
  form.addEventListener("submit", event => {
    if (!isBlocked()) return;
    event.preventDefault();
    message.textContent = emptyText;
    message.hidden = false;
    clearTimeout(messageTimer);
    messageTimer = setTimeout(() => { message.hidden = true; }, 3000);
    form.querySelector("input:not([type=hidden])").focus();
  });
  window.addEventListener("pageshow", update);
  update();
});

// The page size of a list applies as soon as it is chosen.
document.querySelectorAll(".js-page-size select").forEach(select => {
  select.addEventListener("change", () => select.form.submit());
});
