import { Routes } from '@angular/router';
import { adminGuard } from './auth/admin.guard';
import { ProjectActionsComponent } from './projects/project-actions.component';

export const routes: Routes = [
  { path: 'projects/:id', component: ProjectActionsComponent },
  { path: 'admin', canActivate: [adminGuard], loadComponent: () => import('./app.component').then((m) => m.AppComponent) },
];
