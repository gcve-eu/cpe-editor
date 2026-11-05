// Show validation errors inside the field components of _ui.html, instead of
// the browser's bubbles. The server can render the same state with `error=`.
(() => {
  "use strict";
  const selector = ".field input, .field select, .field textarea";

  function setError(control, message) {
    const field = control.closest(".field");
    let error = field.querySelector(".field-error");
    if (message && !error) {
      error = document.createElement("small");
      error.className = "field-error";
      error.id = `${control.id || control.name}-error`;
      error.setAttribute("role", "alert");
      field.append(error);
    }
    if (error) {
      if (message) error.textContent = message;
      else error.remove();
    }
    field.classList.toggle("field-invalid", Boolean(message));
    if (message) {
      control.setAttribute("aria-invalid", "true");
      control.setAttribute("aria-describedby", error.id);
    } else {
      control.removeAttribute("aria-invalid");
      const hint = field.querySelector(".field-hint");
      if (hint) control.setAttribute("aria-describedby", hint.id);
      else control.removeAttribute("aria-describedby");
    }
  }

  // Forms that keep their submit buttons disabled until required fields have a value.
  document.querySelectorAll("form[data-disable-until-filled]").forEach(form => {
    const update = () => {
      const ready = [...form.querySelectorAll("[required]")].every(control => control.value.trim());
      form.querySelectorAll('button[type="submit"]').forEach(button => {
        button.disabled = !ready;
        button.title = ready ? "" : "Fill in the required fields.";
      });
    };
    form.addEventListener("input", update);
    form.addEventListener("change", update);
    update();
  });

  const focusTarget = control => control.closest(".field").querySelector(".site-select-button") || control;

  document.addEventListener("invalid", event => {
    const control = event.target;
    if (!control.matches?.(selector)) return;
    event.preventDefault();
    setError(control, control.validity.valueMissing ? "This field is required." : control.validationMessage);
    const first = control.form && [...control.form.elements].find(item => item.matches(selector) && !item.validity.valid);
    if (first === control) focusTarget(control).focus();
  }, true);

  const clear = event => {
    if (event.target.matches?.(selector) && event.target.closest(".field-invalid")) setError(event.target, "");
  };
  document.addEventListener("input", clear);
  document.addEventListener("change", clear);
})();
