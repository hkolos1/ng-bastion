export function legacyWidget(el: HTMLElement): void {
  // ngbastion-ignore-next-line NGB003 -- legacy widget renders only admin-authored fragments, tracked in SEC-142
  el.innerHTML = window.name;
}

export function unjustified(el: HTMLElement): void {
  el.innerHTML = document.referrer; // ngbastion-ignore NGB003
}
