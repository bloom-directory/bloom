/* Local snapshot interactions only. No fetches, wallet requests, or signing. */
'use strict';
document.documentElement.classList.add('interactive');
for (const explorer of document.querySelectorAll('[data-switcher]')) {
  const buttons = [...explorer.querySelectorAll('[data-select]')];
  const panels = [...explorer.querySelectorAll('[data-panel]')];
  function select(key) {
    buttons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.select === key)));
    panels.forEach(panel => { panel.hidden = panel.dataset.panel !== key; });
  }
  buttons.forEach(button => button.addEventListener('click', () => select(button.dataset.select)));
  if (buttons.length) select(buttons[0].dataset.select);
  for (const panel of panels) {
    const ranges = [...panel.querySelectorAll('[data-range]')];
    const choices = [...panel.querySelectorAll('[data-days]')];
    function range(days) {
      choices.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.days === days)));
      ranges.forEach(content => { content.hidden = content.dataset.range !== days; });
    }
    choices.forEach(button => button.addEventListener('click', () => range(button.dataset.days)));
    range('30');
  }
}
for (const svg of document.querySelectorAll('svg[data-points]')) {
  const points = JSON.parse(svg.dataset.points);
  svg.setAttribute('tabindex', '0');
  svg.setAttribute('aria-label', svg.getAttribute('aria-label') + '. Use left and right arrow keys to inspect observations.');
  const output = svg.closest('.history-chart').querySelector('output');
  const cursor = svg.querySelector('.chart-cursor');
  const marker = svg.querySelector('.chart-selected');
  let selected = points.length - 1;
  function show(index) {
    selected = Math.max(0, Math.min(points.length - 1, index));
    const p = points[selected];
    cursor.setAttribute('x1', p.x); cursor.setAttribute('x2', p.x);
    marker.setAttribute('cx', p.x); marker.setAttribute('cy', p.y);
    output.textContent = p.label;
  }
  svg.addEventListener('pointermove', event => {
    const bounds = svg.getBoundingClientRect();
    const x = (event.clientX - bounds.left) / bounds.width * 600;
    let index = 0;
    points.forEach((p, i) => { if (Math.abs(p.x - x) < Math.abs(points[index].x - x)) index = i; });
    show(index);
  });
  svg.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    show(event.key === 'Home' ? 0 : event.key === 'End' ? points.length - 1 : selected + (event.key === 'ArrowLeft' ? -1 : 1));
  });
}
const activity = document.querySelector('.activity-browser');
if (activity) {
  const buttons = [...activity.querySelectorAll('[data-filter]')];
  const rows = [...activity.querySelectorAll('[data-outcome]')];
  const wallet = document.querySelector('#activity-wallet');
  const search = document.querySelector('#activity-search');
  let filter = buttons.some(button => button.dataset.filter === location.hash.slice(1)) ? location.hash.slice(1) : 'all';
  function apply() {
    let count = 0;
    buttons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.filter === filter)));
    rows.forEach(row => {
      const outcome = filter === 'all' || row.dataset.outcome === filter || (filter === 'failed' && row.dataset.outcome === 'reverted');
      row.hidden = !(outcome && (wallet.value === 'all' || wallet.value === row.dataset.wallet) && row.dataset.search.includes(search.value.trim().toLowerCase()));
      if (!row.hidden) count++;
    });
    document.querySelector('#activity-count').textContent = `${count} of ${rows.length} operations`;
    activity.querySelector('.activity-empty').hidden = count !== 0;
  }
  buttons.forEach(button => button.addEventListener('click', () => { filter = button.dataset.filter; apply(); }));
  wallet.addEventListener('change', apply);
  search.addEventListener('input', apply);
  window.addEventListener('hashchange', () => {
    const hash = location.hash.slice(1);
    if (buttons.some(button => button.dataset.filter === hash)) { filter = hash; apply(); }
  });
  apply();
}
