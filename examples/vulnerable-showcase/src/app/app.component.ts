import { Component } from '@angular/core';
import { ProfileCardComponent } from './xss/profile-card.component';
import { HelpFrameComponent } from './messaging/help-frame.component';

@Component({
  selector: 'app-root',
  imports: [ProfileCardComponent, HelpFrameComponent],
  template: `<app-profile-card /><app-help-frame />`,
})
export class AppComponent {}
