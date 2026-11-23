import { provideNgBastionTools } from './app/webmcp/tools';
import { bootstrapApplication } from '@angular/platform-browser';
import { App } from './app/app';
import { appConfig } from './app/app.config';

bootstrapApplication(App, { providers: [...appConfig.providers, provideNgBastionTools()] }).catch((error: unknown) => console.error(error));
