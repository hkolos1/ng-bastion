import { Component, HostListener } from '@angular/core';

@Component({
  selector: 'app-help-frame',
  // NGB010: allow-scripts + allow-same-origin lets same-origin content remove its own sandbox.
  template: `<iframe src="/help/index.html" sandbox="allow-scripts allow-same-origin" title="Help"></iframe>`,
})
export class HelpFrameComponent {
  // NGB007 + NGB009 + NGB011 + NGB012: any window can post a message that redirects the user.
  @HostListener('window:message', ['$event'])
  onMessage(event: MessageEvent): void {
    if (event.data?.type === 'navigate') {
      window.location.href = event.data.url;
    }
  }

  // NGB006: the session token is broadcast to whatever page is in the parent window.
  shareSession(token: string): void {
    window.parent.postMessage({ type: 'session', authToken: token }, '*');
  }
}
