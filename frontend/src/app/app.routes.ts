import { Routes } from '@angular/router';
import { authGuard } from './guards/auth.guard';
import { guestGuard } from './guards/guest.guard';
import { LoginComponent } from './pages/login/login.component';
import { SignComponent } from './pages/sign/sign.component';
import { VerifyComponent } from './pages/verify/verify.component';
import { LogsComponent } from './pages/logs/logs.component';
import { AddVersionComponent } from './pages/add-version/add-version.component';
import { BenchmarkComponent } from './pages/benchmark/benchmark.component';

export const routes: Routes = [
  { path: 'login', component: LoginComponent, canActivate: [guestGuard] },
  { path: 'sign', component: SignComponent, canActivate: [authGuard] },
  { path: 'add-version', component: AddVersionComponent, canActivate: [authGuard] },
  { path: 'verify', component: VerifyComponent, canActivate: [authGuard] },
  { path: 'logs', component: LogsComponent, canActivate: [authGuard] },
  { path: 'benchmark', component: BenchmarkComponent, canActivate: [authGuard] },
  { path: 'admin-dashboard', loadComponent: () => import('./pages/admin-dashboard/admin-dashboard.component').then(c => c.AdminDashboardComponent), canActivate: [authGuard] },
  { path: 'public-verify', loadComponent: () => import('./pages/public-verify/public-verify.component').then(c => c.PublicVerifyComponent) },
  { path: '', redirectTo: 'sign', pathMatch: 'full' },
  { path: '**', redirectTo: 'sign' },
];
