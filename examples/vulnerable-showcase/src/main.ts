import { bootstrapApplication, provideClientHydration, withHttpTransferCacheOptions } from '@angular/platform-browser';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app/app.component';
import { authInterceptor } from './app/auth/auth.interceptor';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter([]),
    provideHttpClient(withInterceptors([authInterceptor])),
    // NGB020: per-user responses fetched with Authorization headers are serialized into the page.
    provideClientHydration(withHttpTransferCacheOptions({ includeRequestsWithAuthHeaders: true })),
  ],
});
