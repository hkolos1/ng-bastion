import { Component, HostListener } from '@angular/core';

const PAYMENT_ORIGIN = 'https://pay.example.com';

@Component({
  selector: 'app-checkout-frame',
  template: `<iframe src="https://pay.example.com/embed" title="Payment"></iframe>`,
})
export class CheckoutFrameComponent {
  @HostListener('window:message', ['$event'])
  onMessage(event: MessageEvent): void {
    if (event.origin !== PAYMENT_ORIGIN) return;
    if (typeof event.data?.returnPath !== 'string') return;
    const target = new URL(event.data.returnPath, window.location.origin);
    if (target.origin !== window.location.origin) return;
    window.location.assign(target.pathname);
  }
}
