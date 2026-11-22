import { Injectable } from '@angular/core';

export interface CardDetails {
  cardNumber: string;
  cvv: string;
  expiry: string;
}

@Injectable({ providedIn: 'root' })
export class CheckoutService {
  /** NGB015: full card data persisted in the browser. */
  rememberCard(card: CardDetails): void {
    sessionStorage.setItem('checkout', JSON.stringify({ cardNumber: card.cardNumber, cvv: card.cvv }));
  }

  /** Safe: only an opaque PSP reference and display metadata are kept. */
  rememberReference(paymentMethodId: string, last4: string): void {
    sessionStorage.setItem('payment_method', JSON.stringify({ paymentMethodId, last4 }));
  }
}
