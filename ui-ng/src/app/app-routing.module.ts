import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { AuthenticationPageComponent } from './components/authentication-page/authentication-page.component';
import { ErrorPageComponent } from './components/error-page/error-page.component';
import { LogoutPageComponent } from './components/logout-page/logout-page.component';

const routes: Routes = [
  { path: 'auth', redirectTo: 'error/'},
  { path: 'auth/:transactionId', component: AuthenticationPageComponent },
  { path: 'error', redirectTo: 'error/'},
  { path: 'error/:errorId', component: ErrorPageComponent },
  { path: 'logout', component: LogoutPageComponent },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
