(() => {
  const list = document.querySelector("[data-network-list]");
  if (!list) return;

  const rows = list.querySelector("[data-network-rows]");
  const buttons = [...list.querySelectorAll("button[data-sort]")];
  const status = list.querySelector(".sort-status");
  const labels = {
    name: "Network",
    "fees-all": "Fees · all time",
    "fees-day": "Fees · 24h",
    "dex-day": "DEX volume · 24h",
  };

  const sort = (key, direction) => {
    const items = [...rows.querySelectorAll(".network-row")];
    items.sort((a, b) => {
      let comparison;
      if (key === "name") {
        comparison = a.dataset.name.localeCompare(b.dataset.name);
      } else {
        const left = a.dataset[key.replace(/-([a-z])/g, (_, c) => c.toUpperCase())];
        const right = b.dataset[key.replace(/-([a-z])/g, (_, c) => c.toUpperCase())];
        if (left === "" && right !== "") return 1;
        if (right === "" && left !== "") return -1;
        comparison = left === "" ? 0 : Number(left) - Number(right);
      }
      if (comparison === 0) comparison = a.dataset.name.localeCompare(b.dataset.name);
      return direction === "asc" ? comparison : -comparison;
    });
    items.forEach((item) => rows.append(item));
    buttons.forEach((button) => {
      const active = button.dataset.sort === key;
      button.setAttribute("aria-pressed", String(active));
      button.dataset.direction = active ? direction : "";
      button.querySelector("span").textContent = active ? (direction === "asc" ? "↑" : "↓") : "↕";
    });
    status.textContent = `Sorted by ${labels[key]}, ${direction === "asc" ? "ascending" : "descending"}.`;
  };

  buttons.forEach((button) => button.addEventListener("click", () => {
    const key = button.dataset.sort;
    const direction = button.getAttribute("aria-pressed") === "true" && button.dataset.direction === "desc"
      ? "asc"
      : "desc";
    sort(key, direction);
  }));
})();

(() => {
  // Deep links name a wallet (`receive.html#wallet-main`). Without script
  // the picker still works by hand; with script the linked wallet is
  // selected on arrival and on hash changes.
  const shell = document.querySelector("[data-wallet-picker]");
  if (!shell) return;
  const select = () => {
    const match = location.hash.match(/^#wallet-(.+)$/);
    if (!match) return;
    const input = document.getElementById(`pick-${match[1]}`);
    if (input) input.checked = true;
  };
  window.addEventListener("hashchange", select);
  select();
})();
