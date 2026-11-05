// Cards inside [data-accordion] start open and collapse independently. A section
// that appears, or holds an invalid field, opens by itself.
document.querySelectorAll("[data-accordion]").forEach(root => {
  const cards = [...root.querySelectorAll(":scope > .card")];
  const isShown = card => card.style.display !== "none";

  function expand(card) {
    card.classList.remove("is-collapsed");
    card.querySelector(".accordion-toggle").setAttribute("aria-expanded", "true");
    card.querySelector(".accordion-body").hidden = false;
  }

  cards.forEach((card, index) => {
    const header = card.querySelector(":scope > .card-header");
    const body = document.createElement("div");
    body.className = "accordion-body";
    body.id = `accordion-body-${index}`;
    body.append(...[...card.children].filter(child => child !== header));
    card.append(body);
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "accordion-toggle secondary";
    toggle.setAttribute("aria-controls", body.id);
    toggle.setAttribute("aria-label", `Show or hide ${header.querySelector("h1, h2").textContent}`);
    toggle.innerHTML = '<i class="fa-solid fa-chevron-down" aria-hidden="true"></i>';
    header.append(toggle);
    header.addEventListener("click", event => {
      if (event.target.closest("a, .card-actions")) return;
      if (toggle.getAttribute("aria-expanded") === "true") {
        card.classList.add("is-collapsed");
        toggle.setAttribute("aria-expanded", "false");
        body.hidden = true;
      } else {
        expand(card);
      }
    });
  });

  cards.forEach(expand);

  new MutationObserver(records => {
    records.forEach(({target}) => {
      if (cards.includes(target) && isShown(target)) expand(target);
    });
  }).observe(root, {subtree: true, attributes: true, attributeFilter: ["style"]});

  // Registered on document before form-fields.js, so the section is open by the
  // time that script moves focus to the first invalid field.
  document.addEventListener("invalid", event => {
    if (!root.contains(event.target)) return;
    const form = event.target.form;
    const first = form && [...form.elements].find(item => item.willValidate && !item.validity.valid);
    if (first === event.target) expand(event.target.closest(".card"));
  }, true);
});
