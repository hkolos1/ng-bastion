import { Component } from '@angular/core';

@Component({
  selector: 'app-legacy-login',
  // NGB038: the password is posted natively over plain HTTP.
  template: `
    <form action="http://sso.example.com/login" method="post">
      <input name="username" autocomplete="username">
      <input type="password" name="password" autocomplete="current-password">
    </form>`,
})
export class LegacyLoginComponent {}
