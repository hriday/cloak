(function () {
  if (!window.CLOAK_LOGGED_IN) return;
  if (sessionStorage.getItem("cloak.import_attempted")) return;
  const items = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key.startsWith("cloak.progress.")) continue;
    const [, , algo, lesson] = key.split(".");
    try {
      const parsed = JSON.parse(localStorage.getItem(key));
      items.push({ algorithm_slug: algo, lesson_slug: lesson, state: parsed.state, current_step_order: parsed.current_step_order });
    } catch {}
  }
  if (items.length === 0) {
    sessionStorage.setItem("cloak.import_attempted", "1");
    return;
  }
  const csrf = document.querySelector("meta[name=csrf-token]")?.content;
  fetch("/api/progress/import/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
    body: JSON.stringify({ items }),
  }).then((r) => {
    if (r.ok) {
      for (const it of items) localStorage.removeItem(`cloak.progress.${it.algorithm_slug}.${it.lesson_slug}`);
    }
    sessionStorage.setItem("cloak.import_attempted", "1");
  });
})();
