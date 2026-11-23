import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({ selector: 'app-plugin-host', template: '' })
export class PluginHostComponent {
  private readonly route = inject(ActivatedRoute);

  start(): Worker {
    // NGB075: the query string chooses the script the worker runs with this origin's privileges.
    return new Worker(this.route.snapshot.queryParams['plugin']);
  }
}
