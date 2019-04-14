import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { HttpClientModule }    from '@angular/common/http';
import { FormsModule } from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { AuthenticationPageComponent } from './authentication-page/authentication-page.component';

import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
import { AlertBoxComponent } from './alert-box/alert-box.component';
import { LoginPasswordFormComponent } from './login-password-form/login-password-form.component';
import { U2fFormComponent } from './u2f-form/u2f-form.component';
import { ErrorPageComponent } from './error-page/error-page.component';
import { LogoutPageComponent } from './logout-page/logout-page.component';

@NgModule({
  declarations: [
    AppComponent,
    AuthenticationPageComponent,
    AlertBoxComponent,
    LoginPasswordFormComponent,
    U2fFormComponent,
    ErrorPageComponent,
    LogoutPageComponent,
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    NgbModule,
    FormsModule,
    HttpClientModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
