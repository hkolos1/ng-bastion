import { Component, HostListener } from '@angular/core';

@Component({
  selector: 'app-checkout-frame',
  template: `<iframe src="https://pay.example.com/embed" title="Payment"></iframe>`,
})
export class CheckoutFrameComponent {
  @HostListener('window:message', ['$event'])
  onMessage(event: MessageEvent): void {
    if (event.data?.type === 'done') {
      window.location.href = event.data.returnUrl;
    }
  }
}
