import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { PreviewComponent } from './preview/preview.component';

@Component({
  selector: 'app-root',
  imports: [PreviewComponent],
  templateUrl: './app.component.html',
})
export class AppComponent {
  private readonly route = inject(ActivatedRoute);
  /** Safe: bound with [innerHTML], which Angular sanitizes. */
  readonly note = this.route.snapshot.queryParamMap.get('note') ?? '';
  readonly items = ['a', 'b'];
}
