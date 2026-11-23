import { bootstrapApplication, provideClientHydration, withHttpTransferCacheOptions } from '@angular/platform-browser';
import { provideHttpClient, withInterceptors, withNoXsrfProtection } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';
import { authInterceptor } from './app/auth/auth.interceptor';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes),
    // NGB021: XSRF header interceptor disabled while the API uses cookie sessions (withCredentials in ProjectsApi).
    provideHttpClient(withInterceptors([authInterceptor]), withNoXsrfProtection()),
    // NGB020: per-user responses fetched with Authorization headers are serialized into the page.
    provideClientHydration(withHttpTransferCacheOptions({ includeRequestsWithAuthHeaders: true })),
  ],
});
