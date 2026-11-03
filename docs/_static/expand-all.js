// "Expand all / Collapse all" for requirement cards (sphinx-needs collapse toggles).
document.addEventListener("DOMContentLoaded", function () {
  var cards = document.querySelectorAll("table.need");
  if (cards.length < 2) return;
  var article = document.querySelector("article");
  var first = document.querySelector("div.need_container");
  if (!article || !first) return;
  var bar = document.createElement("div");
  bar.className = "need-toolbar";
  function make(label, expand) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", function () {
      cards.forEach(function (card) {
        var meta = card.querySelector("tr.meta");
        if (!meta) return;
        var hidden = meta.classList.contains("collapse_is_hidden");
        if (hidden === expand) {
          var icon = card.querySelector(hidden ? "span.needs.collapsed" : "span.needs.visible");
          // the visible one is the clickable icon in the current state
          (card.querySelector("span.needs.collapsed:not(.collapse_is_hidden), span.needs.visible:not(.collapse_is_hidden)") || icon).click();
        }
      });
    });
    return b;
  }
  bar.appendChild(make("Expand all details", true));
  bar.appendChild(make("Collapse all details", false));
  first.parentNode.insertBefore(bar, first);
});
