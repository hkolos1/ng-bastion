import { Component, HostListener } from '@angular/core';

const PAYMENT_ORIGIN = 'https://pay.example.com';

@Component({
  selector: 'app-checkout-frame',
  template: `
    <iframe src="https://pay.example.com/embed" title="Payment">
    </iframe>
  `,
})
export class CheckoutFrameComponent {
  @HostListener('window:message', ['$event'])
  onMessage(event: MessageEvent): void {
    if (event.origin !== PAYMENT_ORIGIN) return;
    if (typeof event.data?.returnPath !== 'string') return;

    const here = window.location.origin;
    const target = new URL(event.data.returnPath, here);
    if (target.origin !== here) return;

    window.location.assign(target.pathname);
  }
}
