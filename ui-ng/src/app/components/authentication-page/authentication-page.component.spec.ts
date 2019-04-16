import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthenticationPageComponent } from './authentication-page.component';
import { AlertBoxComponent } from '../alert-box/alert-box.component';
import { FormsModule } from '@angular/forms';
import { UsernamePasswordFormComponent } from '../username-password-form/username-password-form.component';
import { U2fFormComponent } from '../u2f-form/u2f-form.component';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
import { HttpClientModule } from '@angular/common/http';
import { AppRoutingModule } from 'src/app/app-routing.module';
import { ConsentPageComponent } from '../consent-page/consent-page.component';
import { ErrorPageComponent } from '../error-page/error-page.component';
import { LogoutPageComponent } from '../logout-page/logout-page.component';

describe('AuthenticationPageComponent', () => {
  let component: AuthenticationPageComponent;
  let fixture: ComponentFixture<AuthenticationPageComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      imports: [ FormsModule, NgbModule, HttpClientModule, AppRoutingModule ],
      declarations: [
        AuthenticationPageComponent,
        AlertBoxComponent,
        UsernamePasswordFormComponent,
        U2fFormComponent,
        ErrorPageComponent,
        LogoutPageComponent,
        ConsentPageComponent,
      ]})
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(AuthenticationPageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
