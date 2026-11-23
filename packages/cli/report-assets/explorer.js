/* global document, window, Option */
(() => {
  'use strict';
  const byId = (id) => document.getElementById(id);
  const rows = byId('rows');
  const filters = Array.from(document.querySelectorAll('[data-filter]'));
  const cards = Array.from(rows.children, (element) => ({
    element,
    fields: element.dataset,
    text: element.textContent.toLowerCase(),
  }));
  const severity = ['critical', 'high', 'medium', 'low', 'info'];
  const confidence = ['high', 'medium', 'low'];
  const perPage = 50;
  let page = 0;
  let matches = cards;
  let sorted = cards;
  let lastSort;
  for (const filter of filters) {
    const values = new Set(cards.map((card) => card.fields[filter.id]));
    for (const value of Array.from(values).sort()) filter.add(new Option(value, value));
  }
  function display() {
    const start = page * perPage;
    rows.replaceChildren(...matches.slice(start, start + perPage).map((card) => card.element));
    byId('matches').textContent = matches.length
      ? `Showing ${start + 1}–${Math.min(start + perPage, matches.length)} of ${matches.length} findings`
      : 'No matching findings';
    byId('pages').hidden = matches.length <= perPage;
    byId('prev').disabled = page === 0;
    byId('next').disabled = start + perPage >= matches.length;
  }
  function update() {
    const query = byId('search').value.trim().toLowerCase();
    const sort = byId('sort').value;
    const active = filters.filter((filter) => filter.value);
    if (sort !== lastSort) {
      lastSort = sort;
      sorted = [...cards].sort((a, b) => {
        const x = a.fields,
          y = b.fields;
        let order = 0;
        if (sort === 'Severity') order = severity.indexOf(x.severity) - severity.indexOf(y.severity);
        if (sort === 'Confidence') order = confidence.indexOf(x.confidence) - confidence.indexOf(y.confidence);
        if (sort === 'Rule ID') order = x.rule.localeCompare(y.rule);
        return (
          order ||
          x.file.localeCompare(y.file) ||
          Number(x.line) - Number(y.line) ||
          Number(x.column) - Number(y.column)
        );
      });
    }
    matches = sorted.filter(
      (card) => card.text.includes(query) && active.every((filter) => card.fields[filter.id] === filter.value),
    );
    page = 0;
    display();
  }
  byId('controls').hidden = false;
  byId('controls').addEventListener('input', update);
  byId('reset').onclick = () => {
    for (const filter of filters) filter.selectedIndex = 0;
    byId('sort').selectedIndex = 0;
    byId('search').value = '';
    update();
  };
  byId('prev').onclick = () => {
    page--;
    display();
  };
  byId('next').onclick = () => {
    page++;
    display();
  };
  const theme = byId('theme');
  theme.hidden = false;
  theme.onclick = () => {
    const current =
      document.documentElement.dataset.theme ??
      (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    document.documentElement.dataset.theme = current === 'dark' ? 'light' : 'dark';
  };
  let opened;
  window.addEventListener('beforeprint', () => {
    if (opened) return;
    rows.replaceChildren(...matches.map((card) => card.element));
    opened = Array.from(document.querySelectorAll('details:not([open])'));
    for (const detail of opened) detail.open = true;
  });
  window.addEventListener('afterprint', () => {
    if (!opened) return;
    for (const detail of opened) detail.open = false;
    opened = undefined;
    display();
  });
  update();
})();
